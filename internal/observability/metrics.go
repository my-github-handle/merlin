// Package observability provides metrics and structured logging.
package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds Merlin's Prometheus collectors.
type Metrics struct {
	reg              prometheus.Registerer
	gatherer         prometheus.Gatherer
	pushTotal        *prometheus.CounterVec
	scanDuration     prometheus.Histogram
	assembleDuration prometheus.Histogram
	queueWait        prometheus.Histogram
	promoteDuration  prometheus.Histogram
	scannerDBAge     prometheus.Gauge
	pendingPromotes  prometheus.Gauge
	scratchBytes     prometheus.Gauge
	acrPush          *prometheus.CounterVec
	requestsTotal    *prometheus.CounterVec
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
			Name: "merlin_scan_duration_seconds",
			Help: "Scanner scan duration in seconds.",
			// Buckets must span the full gate timeout (default 5m) AND resolve finely
			// around the 30s client ResponseHeaderTimeout, which is the number that
			// decides whether a push can succeed at all. DefBuckets topped out at 10s:
			// every real scan landed in +Inf and p95 was unrecoverable.
			Buckets: []float64{1, 2.5, 5, 10, 15, 20, 25, 30, 45, 60, 90, 120, 180, 300, 600},
		}),
		assembleDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "merlin_assemble_duration_seconds",
			Help:    "Time to assemble the staged image into an OCI layout.",
			Buckets: []float64{0.5, 1, 2.5, 5, 10, 15, 20, 30, 60, 120, 300},
		}),
		// Queue wait is the time a push spends waiting for one of scan_pool_size
		// slots. It is deliberately excluded from scan duration (see router/pool.go —
		// "queue wait must not consume scan time") and so was previously invisible —
		// yet with 2 slots against a burst it is expected to be the largest term in
		// the blocked manifest-PUT window. Buckets must reach the full gate timeout:
		// queue wait gets its OWN 5m budget on top of the scan's.
		queueWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "merlin_gate_queue_wait_seconds",
			Help:    "Time a push waited for a scan slot before its scan began.",
			Buckets: []float64{0.1, 0.5, 1, 2.5, 5, 10, 15, 20, 30, 45, 60, 120, 300, 600},
		}),
		promoteDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "merlin_promote_duration_seconds",
			Help:    "Time to push the passed image (blobs + manifest) to ACR.",
			Buckets: []float64{0.5, 1, 2.5, 5, 10, 15, 20, 30, 60, 120, 300, 600},
		}),
		scannerDBAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "merlin_scanner_db_age_days",
			Help: "Age of the scanner vulnerability DB in days.",
		}),
		// The two levels deferred promotion made load-bearing. Publication now outlives
		// the manifest PUT, so a pending job pins an OCI layout plus an extracted rootfs
		// on the scratch volume long after its client saw 201 — volume occupancy no
		// longer tracks in-flight requests, and the pending bound is tuned from these.
		pendingPromotes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "merlin_promote_pending",
			Help: "Promotions waiting for the worker (queue depth).",
		}),
		scratchBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "merlin_scratch_bytes",
			Help: "Bytes held by Merlin's scratch directories on the local volume.",
		}),
		// registry names WHICH tenant registry a push went to and result names WHY it
		// failed (acr.PushErrorClass). With only a result label, a tenant losing
		// AcrPush looked exactly like a network blip — see PR 2431, where an
		// unlabelled error counter hid a persistent 401 for two days. Cardinality is
		// one registry per tenant (a handful) x 6 closed classes.
		acrPush: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "merlin_acr_push_total",
			Help: "ACR push attempts by registry and result (ok, auth, not_found, timeout, network, other).",
		}, []string{"registry", "result"}),
		// Every other counter here is decision-shaped, so a request that fails BEFORE a
		// decision exists — 401 at auth, 404 on an unknown host, 503 shed at the upload
		// gate, 405 — is currently invisible: the gate looks idle while clients are being
		// turned away. This is the only metric that sees those.
		//
		// route is a bounded CLASS, never the raw path: paths carry repo names, tags and
		// digests, so labelling them would grow a new time series per image pushed.
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "merlin_requests_total",
			Help: "Docker V2 requests by method, route class, and response status.",
		}, []string{"method", "route", "status"}),
	}
	reg.MustRegister(m.pushTotal, m.scanDuration, m.assembleDuration, m.queueWait,
		m.promoteDuration, m.scannerDBAge, m.pendingPromotes, m.scratchBytes, m.acrPush,
		m.requestsTotal)
	return m
}

func (m *Metrics) ObservePush(passed bool) {
	outcome := "rejected"
	if passed {
		outcome = "passed"
	}
	m.pushTotal.WithLabelValues(outcome).Inc()
}

// ObservePushError counts a push whose gate did NOT complete (scan timeout,
// assemble/ACR failure, pool saturation) — a third outcome distinct from
// passed/rejected, so infra failures are visible in merlin_push_decisions_total.
func (m *Metrics) ObservePushError() { m.pushTotal.WithLabelValues("error").Inc() }

func (m *Metrics) ObserveScanDuration(seconds float64) { m.scanDuration.Observe(seconds) }
func (m *Metrics) SetScannerDBAgeDays(days float64)    { m.scannerDBAge.Set(days) }

// The three observers below cover the phases of the blocked manifest-PUT window
// that scan duration excludes: image assembly, the wait for a scan slot, and the
// ACR push. Consumers reach them through optional interface assertions (see
// Outcome.observePushError), so pre-existing metrics fakes keep compiling.
func (m *Metrics) ObserveAssembleDuration(seconds float64) { m.assembleDuration.Observe(seconds) }
func (m *Metrics) ObserveQueueWait(seconds float64)        { m.queueWait.Observe(seconds) }
func (m *Metrics) ObservePromoteDuration(seconds float64)  { m.promoteDuration.Observe(seconds) }

// SetPendingPromotions and SetScratchBytes are sampled on a timer rather than at an
// event, because both are levels held between events: a backlog that stops draining
// changes neither until the next push arrives, which is exactly when it matters.
func (m *Metrics) SetPendingPromotions(n int)  { m.pendingPromotes.Set(float64(n)) }
func (m *Metrics) SetScratchBytes(bytes int64) { m.scratchBytes.Set(float64(bytes)) }

// ObserveACRPush counts one ACR push attempt against the registry it targeted.
// result is an acr.PushErrorClass value: "ok" on success, else the coarse cause.
//
// It is called by whoever actually invokes pusher.Push — SyncPublish inline, or
// the promotion worker when publication is deferred — and NOT by the gate
// outcome. Once promotion moved off the manifest-PUT path, the outcome's
// "publish" step became an enqueue, so counting it here too would have counted
// every async push twice and reported queue health as ACR health.
func (m *Metrics) ObserveACRPush(registry, result string) {
	m.acrPush.WithLabelValues(registry, result).Inc()
}

// ObserveRequest counts one HTTP request by method, bounded route class, and
// response status. Callers must pass a route CLASS, not a path — see the
// requestsTotal registration and docker.routeClass.
func (m *Metrics) ObserveRequest(method, route, status string) {
	m.requestsTotal.WithLabelValues(method, route, status).Inc()
}

// Handler returns the Prometheus metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
}
