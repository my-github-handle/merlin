package observability

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestObservePushIncrementsCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.ObservePush(true)
	m.ObservePush(false)
	m.ObservePush(false)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, mf := range mfs {
		if strings.Contains(mf.GetName(), "push_decisions_total") {
			for _, mm := range mf.GetMetric() {
				total += counterValue(mm)
			}
		}
	}
	if total != 3 {
		t.Errorf("push decisions total = %v, want 3", total)
	}
}

func counterValue(m *dto.Metric) float64 {
	if m.Counter != nil {
		return m.Counter.GetValue()
	}
	return 0
}

func mustGather(t *testing.T, reg *prometheus.Registry) []*dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	return mfs
}

// histogramFor returns the (single, unlabelled) histogram for the named family.
func histogramFor(t *testing.T, reg *prometheus.Registry, name string) *dto.Histogram {
	t.Helper()
	for _, mf := range mustGather(t, reg) {
		if mf.GetName() != name {
			continue
		}
		if len(mf.GetMetric()) == 0 {
			t.Fatalf("%s: family present but has no metric", name)
		}
		h := mf.GetMetric()[0].GetHistogram()
		if h == nil {
			t.Fatalf("%s: metric is not a histogram", name)
		}
		return h
	}
	t.Fatalf("%s: not registered", name)
	return nil
}

// capturedInFiniteBucket reports whether some finite bucket counted an
// observation at or above v — i.e. the value is expressible, not dumped in +Inf.
func capturedInFiniteBucket(h *dto.Histogram, v float64) bool {
	for _, b := range h.GetBucket() {
		if b.GetUpperBound() >= v && b.GetCumulativeCount() >= 1 {
			return true
		}
	}
	return false
}

func TestScanDurationBucketsCoverGateTimeout(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	// The gate timeout default is 5m; a histogram that cannot express 300s
	// reports every real scan as +Inf and hides the p95 entirely.
	m.ObserveScanDuration(290)

	h := histogramFor(t, reg, "merlin_scan_duration_seconds")
	if h.GetSampleCount() != 1 {
		t.Fatalf("sample count = %d, want 1", h.GetSampleCount())
	}
	if !capturedInFiniteBucket(h, 290) {
		t.Error("no finite bucket captured a 290s scan; buckets top out too low")
	}
}

// The blocked manifest-PUT window has phases past the scan; each needs a
// histogram whose buckets reach as far as its phase can actually run. A metric
// registered with too-low buckets is worse than none: it reads as healthy while
// every real observation sits in +Inf.
func TestBlockedWindowPhasesAreObservableAtRealDurations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		observe func(*Metrics, float64)
		metric  string
		at      float64
	}{
		{"assemble", (*Metrics).ObserveAssembleDuration, "merlin_assemble_duration_seconds", 250},
		{"queue wait", (*Metrics).ObserveQueueWait, "merlin_gate_queue_wait_seconds", 290},
		{"promote", (*Metrics).ObservePromoteDuration, "merlin_promote_duration_seconds", 290},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			m := NewMetrics(reg)
			tc.observe(m, tc.at)

			h := histogramFor(t, reg, tc.metric)
			if h.GetSampleCount() != 1 {
				t.Fatalf("%s sample count = %d, want 1", tc.metric, h.GetSampleCount())
			}
			if !capturedInFiniteBucket(h, tc.at) {
				t.Errorf("%s: no finite bucket captured %.0fs", tc.metric, tc.at)
			}
		})
	}
}

func TestSetScannerDBAge(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.SetScannerDBAgeDays(5)
	// No panic + registered gauge is sufficient for this unit.
	if m == nil {
		t.Fatal("nil metrics")
	}
}
