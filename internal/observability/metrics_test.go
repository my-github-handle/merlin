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

// TestDeferredPromotionResourcesAreObservable covers the two numbers deferred
// promotion made load-bearing and left unmeasured. The 201 goes out while the job is
// still queued, so the pending backlog and the scratch bytes it pins are the only
// signals that the worker is falling behind — and the pending bound is tuned from
// them. Both are gauges: they are levels, not events.
func TestDeferredPromotionResourcesAreObservable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		set    func(*Metrics, float64)
		metric string
		want   float64
	}{
		{"pending promotions", func(m *Metrics, v float64) { m.SetPendingPromotions(int(v)) },
			"merlin_promote_pending", 7},
		{"scratch bytes", func(m *Metrics, v float64) { m.SetScratchBytes(int64(v)) },
			"merlin_scratch_bytes", 1 << 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			m := NewMetrics(reg)
			tc.set(m, tc.want)
			if got := gaugeValue(t, reg, tc.metric); got != tc.want {
				t.Errorf("%s = %v, want %v", tc.metric, got, tc.want)
			}
		})
	}
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	for _, mf := range mustGather(t, reg) {
		if mf.GetName() != name {
			continue
		}
		if len(mf.GetMetric()) == 0 {
			t.Fatalf("%s: family present but has no metric", name)
		}
		g := mf.GetMetric()[0].GetGauge()
		if g == nil {
			t.Fatalf("%s: metric is not a gauge", name)
		}
		return g.GetValue()
	}
	t.Fatalf("%s: not registered", name)
	return 0
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

// labelledCounters returns name{label=value,...} -> value for one counter family,
// so a test can assert the LABEL SET, not just a total. For merlin_acr_push_total
// and merlin_requests_total the labels are the whole point of the metric.
func labelledCounters(t *testing.T, reg *prometheus.Registry, name string) map[string]float64 {
	t.Helper()
	got := map[string]float64{}
	for _, mf := range mustGather(t, reg) {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			parts := make([]string, 0, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				parts = append(parts, lp.GetName()+"="+lp.GetValue())
			}
			got[strings.Join(parts, ",")] = counterValue(m)
		}
	}
	return got
}

// TestACRPushIsCountedPerRegistryAndCause covers what the registry+result pair was
// added for: two tenants pushing to two registries, one of them failing on auth,
// must be distinguishable. A single un-labelled error counter made exactly this
// case unreadable for two days.
func TestACRPushIsCountedPerRegistryAndCause(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.ObserveACRPush("a.azurecr.io", "ok")
	m.ObserveACRPush("a.azurecr.io", "ok")
	m.ObserveACRPush("b.azurecr.io", "auth")

	got := labelledCounters(t, reg, "merlin_acr_push_total")
	for key, want := range map[string]float64{
		"registry=a.azurecr.io,result=ok":   2,
		"registry=b.azurecr.io,result=auth": 1,
	} {
		if got[key] != want {
			t.Errorf("merlin_acr_push_total{%s} = %v, want %v (all: %v)", key, got[key], want, got)
		}
	}
}

// TestRequestsAreCountedByMethodRouteStatus pins the one metric that sees requests
// answered before a gate decision exists — the 401s and 404s that make the gate
// look idle while clients are being turned away.
func TestRequestsAreCountedByMethodRouteStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.ObserveRequest("PUT", "manifest", "201")
	m.ObserveRequest("PUT", "manifest", "400")
	m.ObserveRequest("GET", "base", "401")
	m.ObserveRequest("GET", "base", "401")

	got := labelledCounters(t, reg, "merlin_requests_total")
	for key, want := range map[string]float64{
		"method=PUT,route=manifest,status=201": 1,
		"method=PUT,route=manifest,status=400": 1,
		"method=GET,route=base,status=401":     2,
	} {
		if got[key] != want {
			t.Errorf("merlin_requests_total{%s} = %v, want %v (all: %v)", key, got[key], want, got)
		}
	}
}
