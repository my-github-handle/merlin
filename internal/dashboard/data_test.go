package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
)

func TestParseRangeFallback(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in   string
		want Range
		ago  time.Duration
	}{
		{"1d", Range1d, 24 * time.Hour},
		{"7d", Range7d, 7 * 24 * time.Hour},
		{"30d", Range30d, 30 * 24 * time.Hour},
		{"bogus", Range1d, 24 * time.Hour},
		{"", Range1d, 24 * time.Hour},
	} {
		gotR, gotSince := ParseRange(tc.in, now)
		if gotR != tc.want || !gotSince.Equal(now.Add(-tc.ago)) {
			t.Errorf("ParseRange(%q) = (%s,%v), want (%s,%v)", tc.in, gotR, gotSince, tc.want, now.Add(-tc.ago))
		}
	}
}

func TestPassRate(t *testing.T) {
	if got := PassRate(0, 0); got != 0 {
		t.Errorf("PassRate(0,0)=%v want 0", got)
	}
	if got := PassRate(78, 100); got != 78 {
		t.Errorf("PassRate(78,100)=%v want 78", got)
	}
}

type fakeReader struct {
	stats audit.DecisionStats
	cves  []audit.CVECount
	hdr   audit.DecisionHeader
	finds []policy.Finding
	err   error
}

func (f fakeReader) RecentDecisions(context.Context, int) ([]audit.DecisionSummary, error) {
	return []audit.DecisionSummary{{Repo: "a/b", Tag: "v1", Passed: true}}, f.err
}
func (f fakeReader) DecisionStatsSince(context.Context, time.Time) (audit.DecisionStats, error) {
	return f.stats, f.err
}
func (f fakeReader) TopCVEs(context.Context, time.Time, int) ([]audit.CVECount, error) {
	return f.cves, f.err
}
func (f fakeReader) TopPackages(context.Context, time.Time, int) ([]audit.LabeledCount, error) {
	return nil, f.err
}
func (f fakeReader) SeverityTotalsSince(context.Context, time.Time) (audit.SeverityTotals, error) {
	return audit.SeverityTotals{Critical: 1}, f.err
}
func (f fakeReader) FixAvailabilitySince(context.Context, time.Time, int) (audit.FixAvailability, error) {
	return audit.FixAvailability{BySeverity: []audit.FixAvailabilityRow{{Severity: "CRITICAL", Total: 2, Fixable: 1}}}, f.err
}
func (f fakeReader) BaseImagePosture(context.Context, time.Time) ([]audit.BaseImageStat, error) {
	return []audit.BaseImageStat{{BaseImageID: "ubi9", Total: 3, Passed: 2}}, f.err
}
func (f fakeReader) ByIdentity(context.Context, time.Time, int) ([]audit.IdentityStat, error) {
	return []audit.IdentityStat{{Identity: "ci", Total: 3, Passed: 3}}, f.err
}
func (f fakeReader) ByRepo(context.Context, time.Time, int) ([]audit.RepoStat, error) {
	return []audit.RepoStat{{Repo: "a/b", Total: 3, Passed: 2}}, f.err
}
func (f fakeReader) DecisionHeaderByRef(context.Context, string, string) (audit.DecisionHeader, error) {
	return f.hdr, f.err
}
func (f fakeReader) DecisionHeaderByPush(context.Context, string) (audit.DecisionHeader, error) {
	return f.hdr, f.err
}
func (f fakeReader) FindingsByPush(context.Context, string) ([]policy.Finding, error) {
	return f.finds, f.err
}
func (f fakeReader) FindingsByImageRef(context.Context, string, string) ([]policy.Finding, error) {
	return f.finds, f.err
}

func newTestService(fr audit.DashboardReader) *Service {
	reg := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "merlin_trivy_db_age_days", Help: "x"})
	g.Set(4)
	reg.MustRegister(g)
	now := func() time.Time { return time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC) }
	return NewService(fr, reg, now)
}

func TestActivityViewModel(t *testing.T) {
	svc := newTestService(fakeReader{stats: audit.DecisionStats{Total: 10, Passed: 8, Rejected: 2}})
	vm, err := svc.Activity(context.Background(), Range1d)
	if err != nil {
		t.Fatal(err)
	}
	if vm.Stats.PassRate != 80 {
		t.Errorf("PassRate=%v want 80", vm.Stats.PassRate)
	}
	if len(vm.Recent) == 0 {
		t.Error("expected recent decisions")
	}
}

func TestReportViewModelNotFound(t *testing.T) {
	svc := newTestService(fakeReader{hdr: audit.DecisionHeader{Found: false}})
	vm, err := svc.Report(context.Background(), "a/b", "v1", "")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Found {
		t.Error("expected Found=false for missing report")
	}
}
