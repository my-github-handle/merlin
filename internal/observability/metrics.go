// Package observability provides metrics and structured logging.
package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds Merlin's Prometheus collectors.
type Metrics struct {
	reg          prometheus.Registerer
	gatherer     prometheus.Gatherer
	pushTotal    *prometheus.CounterVec
	scanDuration prometheus.Histogram
	trivyDBAge   prometheus.Gauge
	acrPush      *prometheus.CounterVec
}

// NewMetrics registers and returns Merlin's metrics on reg.
func NewMetrics(reg *prometheus.Registry) *Metrics {
	m := &Metrics{
		reg:      reg,
		gatherer: reg,
		pushTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "merlin_push_decisions_total",
			Help: "Total push gate decisions by outcome.",
		}, []string{"outcome"}),
		scanDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "merlin_scan_duration_seconds",
			Help:    "Trivy scan duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}),
		trivyDBAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "merlin_trivy_db_age_days",
			Help: "Age of the Trivy vulnerability DB in days.",
		}),
		acrPush: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "merlin_acr_push_total",
			Help: "ACR push attempts by result.",
		}, []string{"result"}),
	}
	reg.MustRegister(m.pushTotal, m.scanDuration, m.trivyDBAge, m.acrPush)
	return m
}

func (m *Metrics) ObservePush(passed bool) {
	outcome := "rejected"
	if passed {
		outcome = "passed"
	}
	m.pushTotal.WithLabelValues(outcome).Inc()
}

func (m *Metrics) ObserveScanDuration(seconds float64) { m.scanDuration.Observe(seconds) }
func (m *Metrics) SetTrivyDBAgeDays(days float64)      { m.trivyDBAge.Set(days) }

func (m *Metrics) ObserveACRPush(ok bool) {
	result := "error"
	if ok {
		result = "ok"
	}
	m.acrPush.WithLabelValues(result).Inc()
}

// Handler returns the Prometheus metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
}
