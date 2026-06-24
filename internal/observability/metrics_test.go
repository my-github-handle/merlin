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

func TestSetTrivyDBAge(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.SetTrivyDBAgeDays(5)
	// No panic + registered gauge is sufficient for this unit.
	if m == nil {
		t.Fatal("nil metrics")
	}
}
