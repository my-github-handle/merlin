package dashboard

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// The percentage arithmetic on the overview page had no test of its own: toStatsVM was at
// 42.9%, covered only incidentally through Overview's happy path. Every figure it produces
// is a ratio, and every ratio has a denominator that can be zero — the failure mode is a
// page reading "NaN%" or "+Inf%" to an operator during exactly the outage they opened it
// for.

func TestStatsRejectReasonPercentagesAreShareOfRejections(t *testing.T) {
	vm := toStatsVM(audit.DecisionStats{
		Total: 100, Passed: 80, Rejected: 20,
		RejectReasons: []audit.LabeledCount{
			{Label: "critical_cve", Count: 15},
			{Label: "image_too_old", Count: 5},
		},
	})

	if vm.PassRate != 80 {
		t.Errorf("PassRate = %v, want 80", vm.PassRate)
	}
	if len(vm.RejectReasons) != 2 {
		t.Fatalf("got %d reject reasons, want 2", len(vm.RejectReasons))
	}
	// The denominator is REJECTIONS, not total pushes: 15 of 20 rejections is 75%, and
	// dividing by Total instead would quietly render it as 15%.
	if vm.RejectReasons[0].Pct != 75 {
		t.Errorf("critical_cve Pct = %v, want 75 (share of rejections, not of pushes)", vm.RejectReasons[0].Pct)
	}
	if vm.RejectReasons[1].Pct != 25 {
		t.Errorf("image_too_old Pct = %v, want 25", vm.RejectReasons[1].Pct)
	}
	if vm.RejectReasons[0].Label != "critical_cve" || vm.RejectReasons[0].Count != 15 {
		t.Errorf("label/count not carried through: %+v", vm.RejectReasons[0])
	}
}

// Zero denominators produce zero, never NaN or Inf. A gate that rejected nothing is the
// ordinary state of a healthy day, so this branch runs in production constantly.
func TestStatsPercentagesStayFiniteWithNothingToDivideBy(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   audit.DecisionStats
	}{
		{
			name: "reasons present but nothing rejected",
			// Contradictory on purpose: a reason row with Rejected == 0 is what a
			// partially-written aggregation window looks like.
			st: audit.DecisionStats{Total: 10, Passed: 10, Rejected: 0,
				RejectReasons: []audit.LabeledCount{{Label: "critical_cve", Count: 3}}},
		},
		{
			name: "no pushes at all",
			st:   audit.DecisionStats{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := toStatsVM(tc.st)
			if !finite(vm.PassRate) {
				t.Errorf("PassRate = %v, which renders as NaN%% or +Inf%% on the page", vm.PassRate)
			}
			for _, rr := range vm.RejectReasons {
				if !finite(rr.Pct) {
					t.Errorf("%s Pct = %v, which renders as NaN%% or +Inf%%", rr.Label, rr.Pct)
				}
				if rr.Pct != 0 {
					t.Errorf("%s Pct = %v, want 0 when nothing was rejected", rr.Label, rr.Pct)
				}
			}
		})
	}
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// Latency quantiles pass through untouched. They are the one part of StatsVM that is not
// derived, so a transcription slip here is invisible — the page shows a plausible number
// that belongs to a different quantile.
func TestStatsCarriesLatencyQuantilesUnchanged(t *testing.T) {
	vm := toStatsVM(audit.DecisionStats{
		Total: 3, Passed: 3,
		Latency: audit.LatencyPercentiles{P50: 1.5, P95: 9.25, P99: 30},
	})
	if vm.P50 != 1.5 || vm.P95 != 9.25 || vm.P99 != 30 {
		t.Errorf("quantiles = (%v, %v, %v), want (1.5, 9.25, 30)", vm.P50, vm.P95, vm.P99)
	}
}

// sinceCapturingReader records the window the service asked for. The range selector is the
// one control on the page, and it is silently wrong if every range resolves to the same
// window — the numbers still look reasonable.
type sinceCapturingReader struct {
	fakeReader
	since time.Time
}

func (r *sinceCapturingReader) DecisionStatsSince(_ context.Context, since time.Time) (audit.DecisionStats, error) {
	r.since = since
	return r.stats, r.err
}

func TestOverviewAsksForTheWindowTheRangeNames(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		rng Range
		ago time.Duration
	}{
		{Range1d, 24 * time.Hour},
		{Range7d, 7 * 24 * time.Hour},
		{Range30d, 30 * 24 * time.Hour},
		{Range("bogus"), 24 * time.Hour}, // an unknown range falls back to the cheapest window
	} {
		t.Run(string(tc.rng), func(t *testing.T) {
			fr := &sinceCapturingReader{}
			svc := NewService(fr, prometheus.NewRegistry(), func() time.Time { return now })

			if _, err := svc.Overview(context.Background(), tc.rng); err != nil {
				t.Fatal(err)
			}
			if want := now.Add(-tc.ago); !fr.since.Equal(want) {
				t.Errorf("queried since %v, want %v", fr.since, want)
			}
		})
	}
}

// A dead audit store degrades to Errored rather than failing the request, and does not
// leave a half-filled Stats block that would render as a real 0% pass rate.
func TestOverviewMarksErroredWhenStatsQueryFails(t *testing.T) {
	svc := newTestService(fakeReader{err: errors.New("ch down")})
	vm, err := svc.Overview(context.Background(), Range1d)
	if err != nil {
		t.Fatalf("Overview must not return an error on backend failure: %v", err)
	}
	if !vm.Errored {
		t.Error("Errored = false though the audit store was unreachable")
	}
}

// gaugeValue returns 0 for a metric that is not registered — the state on every pod that
// has not completed its first grype DB refresh.
func TestScannerDBAgeIsZeroUntilTheGaugeExists(t *testing.T) {
	svc := newTestServiceWithMetrics(fakeReader{}, false)
	vm, err := svc.Overview(context.Background(), Range1d)
	if err != nil {
		t.Fatal(err)
	}
	if vm.ScannerDBAgeDays != 0 {
		t.Errorf("ScannerDBAgeDays = %v, want 0 before the gauge is set", vm.ScannerDBAgeDays)
	}
}

// A gatherer that fails is not a source of zeroes that look like data: both readers return
// 0 rather than panicking on a nil family list.
func TestMetricReadersSurviveAFailingGatherer(t *testing.T) {
	svc := NewService(fakeReader{}, brokenGatherer{}, func() time.Time { return time.Unix(0, 0) })

	if got := svc.gaugeValue("merlin_scanner_db_age_days"); got != 0 {
		t.Errorf("gaugeValue = %v, want 0 from a failing gatherer", got)
	}
	if got := svc.counterSumWhere("merlin_acr_push_total", "result", "ok", true); got != 0 {
		t.Errorf("counterSumWhere = %v, want 0 from a failing gatherer", got)
	}
}

type brokenGatherer struct{}

func (brokenGatherer) Gather() ([]*dto.MetricFamily, error) {
	return nil, errors.New("gather failed")
}
