package app

import (
	"context"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/config"
	dockeringress "github.com/merlin-gate/merlin/internal/ingress/docker"
	"github.com/merlin-gate/merlin/internal/policy"
)

// Closers run in REVERSE order of acquisition.
//
// R0 listed this as one of three things it could not assert: the closers slice was a
// local inside a 331-line function and cleanup() returned nothing, so the order was
// unobservable from outside the package. R1 gave each component its own closer and put
// them on a named stack, which is what makes this checkable.
//
// The order is load-bearing, not cosmetic. buildAudit pushes the ClickHouse writer,
// then the auditor that buffers into it, then the reader. The auditor drains its queue
// to the writer on Close, so a writer released first would silently discard every
// decision still buffered — scans that ran and left no record.
func TestCloserStackRunsInReverseOrder(t *testing.T) {
	var order []string
	var s closerStack
	s.push(func() { order = append(order, "writer") })
	s.push(func() { order = append(order, "auditor") })
	s.push(func() { order = append(order, "reader") })
	s.closeAll()

	want := []string{"reader", "auditor", "writer"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("close order = %v, want %v", order, want)
	}
}

// A nil closer is ignored rather than panicking, so a component that is switched off
// in config (the alerter) needs no branch at the call site.
func TestCloserStackIgnoresNil(t *testing.T) {
	var ran bool
	var s closerStack
	s.push(nil)
	s.push(func() { ran = true })
	s.push(nil)
	s.closeAll()
	if !ran {
		t.Error("closeAll skipped a real closer after a nil one")
	}
	if n := len(s.fns); n != 1 {
		t.Errorf("stack holds %d closers, want 1: nils were recorded", n)
	}
}

// The metrics sink placed on the outcome must ALSO satisfy ACRPushObserver.
//
// This is the second assertion R0 deferred. The handler reaches the ACR push counter
// by TYPE ASSERTION on outcome.Metrics (Handler.acrPushObserver), so a sink that
// implements only MetricsObserver compiles, wires, passes every push test, and
// silently stops counting real ACR pushes — the metric simply never appears. Narrowing
// outcome.Metrics to an interface value, or wrapping it, is enough to cause it.
func TestOutcomeMetricsAlsoCountACRPushes(t *testing.T) {
	_, metrics := newMetrics()
	outcome := buildOutcome(nil, metrics, nil)

	obs, ok := outcome.Metrics.(dockeringress.ACRPushObserver)
	if !ok {
		t.Fatalf("outcome.Metrics (%T) is not an ACRPushObserver: merlin_acr_push_total would never be written", outcome.Metrics)
	}

	// Not just assignable — reaching the real counter. Scrape and look for the series,
	// because the type assertion succeeding on a sink wired to a different registry
	// would still lose the metric.
	obs.ObserveACRPush("c3devacr.azurecr.io", "ok")

	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if body := rec.Body.String(); !strings.Contains(body, `merlin_acr_push_total{registry="c3devacr.azurecr.io",result="ok"} 1`) {
		t.Errorf("merlin_acr_push_total not in the scrape after an observed push:\n%s", body)
	}
}

// buildOutcome leaves IDGen nil when the caller passes nil, and that difference
// between the two build paths is deliberate for now: the hermetic path falls through
// to the docker package's generator, which degrades to a timestamp when crypto/rand
// fails, while this package's panics. Pin it so the reconciliation is a decision
// rather than a drift.
func TestBuildOutcomeIDGenIsTheCallersChoice(t *testing.T) {
	if got := buildOutcome(nil, nil, nil); got.IDGen != nil {
		t.Error("buildOutcome(nil idGen) set an IDGen; the hermetic path must fall through to docker's")
	}
	if got := buildOutcome(nil, nil, generatePushID); got.IDGen == nil {
		t.Error("buildOutcome dropped the supplied IDGen")
	}
}

// The recorder is a RETURN value, not a field patched after the fact. Everything that
// records a decision — the request path and the promotion worker both — has to pick up
// the same one, so what buildDashboard hands back is what the outcome and the worker
// are built from.
func TestBuildDashboardReturnsTheRecorderInUse(t *testing.T) {
	auditor := audit.NewAuditor(nopWriter{}, 1, func(audit.Decision, error) {})
	defer auditor.Close()

	tests := []struct {
		name      string
		addr      string
		wantSrv   bool
		wantTee   bool
		whyNotTee string
	}{
		{
			name:      "off",
			addr:      "off",
			wantSrv:   false,
			wantTee:   false,
			whyNotTee: "nothing subscribes to a feed that does not exist, so decisions go straight to the auditor",
		},
		{
			name:      "empty is also off",
			addr:      "",
			wantSrv:   false,
			wantTee:   false,
			whyNotTee: "an unset dashboard_addr means off, not bind-to-any",
		},
		{name: "on", addr: "127.0.0.1:0", wantSrv: true, wantTee: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{}
			cfg.Server.DashboardAddr = tc.addr
			reg, _ := newMetrics()
			srv, rec := buildDashboard(cfg, reg, nil, auditor)

			if (srv != nil) != tc.wantSrv {
				t.Errorf("server = %v, want non-nil = %t", srv, tc.wantSrv)
			}
			if rec == nil {
				t.Fatal("recorder is nil: gate decisions would go nowhere")
			}
			isAuditor := rec == dockeringress.DecisionRecorder(auditor)
			if tc.wantTee && isAuditor {
				t.Error("dashboard is on but decisions bypass the live feed")
			}
			if !tc.wantTee && !isAuditor {
				t.Errorf("recorder is not the bare auditor: %s", tc.whyNotTee)
			}
		})
	}
}

// nopWriter is an audit.Writer that accepts and discards. buildDashboard never writes
// through the auditor; it only needs one to tee.
type nopWriter struct{}

func (nopWriter) WriteDecision(context.Context, audit.Decision) error { return nil }
func (nopWriter) WriteFindings(context.Context, audit.Decision, []policy.Finding) error {
	return nil
}
