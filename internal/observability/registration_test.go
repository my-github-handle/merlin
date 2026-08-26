package observability

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
)

// Every collector Metrics holds must be registered on the registry it was built with.
//
// This is the invariant NewMetrics can break silently. A collector that is constructed but
// never registered works perfectly — Inc, Observe and Set all succeed, no error is
// returned and no panic fires — it simply never appears in /metrics. The gate would keep
// recording a figure that nothing can read, and the first sign is an operator finding an
// empty panel during an incident.
//
// The test walks the struct by reflection rather than naming the ten fields, because
// naming them would reproduce exactly the list that has to be kept in sync — the thing
// that goes wrong.
func TestEveryCollectorFieldIsRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Addressable, so unexported fields can be read below.
	v := reflect.ValueOf(m).Elem()
	collectorType := reflect.TypeOf((*prometheus.Collector)(nil)).Elem()

	var checked int
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.Type().Implements(collectorType) {
			continue // reg and gatherer
		}
		name := v.Type().Field(i).Name
		if f.IsNil() {
			t.Errorf("Metrics.%s is nil: NewMetrics did not construct it at all", name)
			continue
		}
		checked++

		// Every collector field is unexported, and reflect refuses to hand out an
		// interface for one. Re-addressing it through its own address is the standard way
		// to read it from a test; the alternative is exporting ten fields for the benefit
		// of this file, which is a worse trade.
		c, ok := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().
			Interface().(prometheus.Collector)
		if !ok {
			t.Errorf("Metrics.%s does not satisfy prometheus.Collector", name)
			continue
		}
		// Re-registering an already-registered collector is an AlreadyRegisteredError.
		// That error is therefore the proof that NewMetrics registered it; a nil error
		// means this field was constructed and then forgotten.
		if err := reg.Register(c); err == nil {
			t.Errorf("Metrics.%s was never registered: it will record silently and never be scraped", name)
		} else if _, dup := err.(prometheus.AlreadyRegisteredError); !dup {
			t.Errorf("Metrics.%s: unexpected registration error %v", name, err)
		}
	}

	// A guard on the guard: if the collector fields were ever replaced with a map or a
	// slice, the loop above would find nothing to check and pass while testing nothing.
	if checked < 10 {
		t.Errorf("only %d collector fields found, want at least 10 — this test has stopped seeing them", checked)
	}
}

// Names and label sets are the contract with Grafana, the ServiceMonitor and the
// dashboard's own queries (internal/dashboard/data.go reads merlin_acr_push_total and
// merlin_scanner_db_age_days by name). Renaming one is not a refactor: it silently empties
// every panel and alert built on it, so the exact strings are pinned here.
func TestRegisteredMetricNamesAndLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Vec metrics emit no series until one is observed, so touch each with a label set of
	// the right arity; a wrong arity panics, which pins the label count too.
	m.ObservePush(true)
	m.ObservePushError()
	m.ObserveScanDuration(1)
	m.ObserveAssembleDuration(1)
	m.ObserveQueueWait(1)
	m.ObservePromoteDuration(1)
	m.SetScannerDBAgeDays(1)
	m.SetPendingPromotions(1)
	m.SetScratchBytes(1)
	m.ObserveACRPush("r.azurecr.io", "ok")
	m.ObserveRequest("PUT", "manifest", "201")

	want := map[string][]string{
		"merlin_push_decisions_total":      {"outcome"},
		"merlin_scan_duration_seconds":     nil,
		"merlin_assemble_duration_seconds": nil,
		"merlin_gate_queue_wait_seconds":   nil,
		"merlin_promote_duration_seconds":  nil,
		"merlin_scanner_db_age_days":       nil,
		"merlin_promote_pending":           nil,
		"merlin_scratch_bytes":             nil,
		"merlin_acr_push_total":            {"registry", "result"},
		"merlin_requests_total":            {"method", "route", "status"},
		"merlin_scan_cache_total":          {"result"},
	}

	got := map[string][]string{}
	for _, mf := range mustGather(t, reg) {
		var labels []string
		if ms := mf.GetMetric(); len(ms) > 0 {
			for _, lp := range ms[0].GetLabel() {
				labels = append(labels, lp.GetName())
			}
		}
		got[mf.GetName()] = labels
	}

	for name, wantLabels := range want {
		gotLabels, ok := got[name]
		if !ok {
			t.Errorf("%s is not exposed: every dashboard panel and alert on it is now empty", name)
			continue
		}
		if !reflect.DeepEqual(gotLabels, wantLabels) {
			t.Errorf("%s labels = %v, want %v", name, gotLabels, wantLabels)
		}
	}
	for name := range got {
		if _, expected := want[name]; !expected {
			t.Errorf("%s is exposed but not listed here: add it, with whatever consumes it", name)
		}
	}
}
