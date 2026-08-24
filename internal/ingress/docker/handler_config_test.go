package docker

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/promote"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
	"github.com/merlin-gate/merlin/internal/tenant"
)

// New rejects configs whose knobs would be INERT.
//
// Every case here is a value an operator can put in a ConfigMap and reasonably
// believe is in force. Under the setters each one was accepted silently and then did
// nothing at all: promotionBacklogFull returns false when promoter is nil,
// acquireUploadSlot returns immediately when uploadSlots is nil, and a
// WWW-Authenticate challenge with an empty realm tells the docker client nowhere to
// fetch a token — so the push stops with no error logged anywhere in Merlin. A
// startup failure is the cheapest place to learn this.
func TestNewRejectsIncoherentConfigs(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	res := testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true})

	tests := []struct {
		name string
		cfg  HandlerConfig
		want string // substring the error must name, so the message points at the field
	}{
		{
			name: "no resolver",
			cfg:  HandlerConfig{},
			want: "Resolver",
		},
		{
			name: "registry issuer with no token realm",
			cfg:  HandlerConfig{Resolver: res, RegistryIssuer: iss, Service: "merlin"},
			want: "TokenRealm",
		},
		{
			name: "registry issuer with no service",
			cfg:  HandlerConfig{Resolver: res, RegistryIssuer: iss, TokenRealm: "https://merlin.example/token"},
			want: "Service",
		},
		{
			name: "promotion bound with no promoter",
			cfg:  HandlerConfig{Resolver: res, MaxPendingPromotions: 16},
			want: "MaxPendingPromotions",
		},
		{
			name: "upload wait with no slots to wait for",
			cfg:  HandlerConfig{Resolver: res, UploadWait: 5 * time.Second},
			want: "UploadWait",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("New accepted an inert config; the knob would do nothing at runtime")
			}
			if h != nil {
				t.Errorf("New returned a handler alongside an error: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q, so an operator cannot tell which field is wrong", err, tc.want)
			}
		})
	}
}

// The couplings New enforces are one-directional: the DEPENDENT half is what must be
// rejected. Setting a bound's precondition without the bound, or a realm without an
// issuer, leaves nothing inert, so New must accept all of these.
func TestNewAcceptsPartialButCoherentConfigs(t *testing.T) {
	res := testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true})
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)

	tests := []struct {
		name string
		cfg  HandlerConfig
		why  string
	}{
		{
			name: "resolver only",
			cfg:  HandlerConfig{Resolver: res},
			why:  "the hermetic wiring and most tests in this package build exactly this",
		},
		{
			name: "promoter with no bound",
			cfg:  HandlerConfig{Resolver: res, Promoter: &fakePromoter{}},
			why:  "an unbounded backlog is a choice, not an inert knob",
		},
		{
			name: "upload concurrency with no wait",
			cfg:  HandlerConfig{Resolver: res, UploadConcurrency: 2},
			why:  "the slots are real; the wait falls back to defaultUploadWait",
		},
		{
			name: "gate timeout with no pool",
			cfg:  HandlerConfig{Resolver: res, GateTimeout: time.Minute},
			why:  "runScan budgets the scan itself with this, pool or no pool",
		},
		{
			name: "registry issuer with realm and service but no token handler",
			cfg: HandlerConfig{
				Resolver:       res,
				RegistryIssuer: iss,
				TokenRealm:     "https://merlin.example/token",
				Service:        "merlin",
			},
			why: "TokenRealm is an absolute URL; another process may serve it",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err != nil {
				t.Errorf("New rejected a coherent config (%s): %v", tc.why, err)
			}
		})
	}
}

// New must WIRE every field of HandlerConfig into the handler.
//
// A field the config carries and New quietly drops is the exact failure this whole
// change exists to remove — it looks configured, reads back as configured in the
// ConfigMap, and does nothing. So populate every field with a value distinct from its
// zero value and check each one arrives.
func TestNewWiresEveryConfiguredField(t *testing.T) {
	var (
		res       = testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true})
		st        = staging.New(nil, nil, func() string { return "u1" })
		rt        = &router.Router{}
		out       = &Outcome{ReportBaseURL: "https://merlin.example"}
		reports   = &fakeReports{}
		requests  = &spyRequests{}
		promoter  = &fakePromoter{}
		pool      = router.NewPool(rt, 3)
		iss       = auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
		tokenHdlr = &TokenHandler{Resolver: res, Issuer: iss}
	)
	const (
		maxUploadBytes = int64(7 << 20)
		uploadConc     = 4
		uploadWait     = 11 * time.Second
		gateTimeout    = 90 * time.Second
		scratchDir     = "/scratch/merlin"
		realm          = "https://merlin.example/token"
		service        = "merlin"
		maxPending     = 5
	)

	h, err := New(HandlerConfig{
		Resolver:             res,
		Store:                st,
		Router:               rt,
		Outcome:              out,
		Reports:              reports,
		Requests:             requests,
		Promoter:             promoter,
		MaxPendingPromotions: maxPending,
		MaxUploadBytes:       maxUploadBytes,
		UploadConcurrency:    uploadConc,
		UploadWait:           uploadWait,
		Pool:                 pool,
		GateTimeout:          gateTimeout,
		ScratchBaseDir:       scratchDir,
		RegistryIssuer:       iss,
		TokenRealm:           realm,
		Service:              service,
		TokenHandler:         tokenHdlr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A Handler field added without a HandlerConfig field to fill it is invisible to
	// the hand-written comparison below, and reflect cannot read unexported fields to
	// find it. Fail loudly instead of passing over a gap.
	if n := reflect.TypeOf(Handler{}).NumField(); n != 21 {
		t.Fatalf("Handler has %d fields, not 21: wire it in New and add it below, or note here why it is not configurable", n)
	}

	// Not compared: mux (built by New, covered by every routing test in this package,
	// and by TestNewRegistersTokenRouteOnlyWhenConfigured); uploadSlots (a channel —
	// its capacity is checked below); indexWait/indexPoll (deliberately not in
	// HandlerConfig, so there is no operator knob to get wrong).
	checks := []struct {
		field     string
		want, got any
	}{
		{"resolver", tenant.Resolver(res), h.resolver},
		{"store", st, h.store},
		{"router", rt, h.router},
		{"outcome", out, h.outcome},
		{"reports", ReportSource(reports), h.reports},
		{"requests", RequestObserver(requests), h.requests},
		{"promoter", promote.Promoter(promoter), h.promoter},
		{"maxPending", maxPending, h.maxPending},
		{"maxUploadBytes", maxUploadBytes, h.maxUploadBytes},
		{"uploadWait", uploadWait, h.uploadWait},
		{"pool", pool, h.pool},
		{"gateTimeout", gateTimeout, h.gateTimeout},
		{"scratchBaseDir", scratchDir, h.scratchBaseDir},
		{"regIssuer", iss, h.regIssuer},
		{"tokenRealm", realm, h.tokenRealm},
		{"service", service, h.service},
		{"tokenHandler", tokenHdlr, h.tokenHandler},
	}
	for _, c := range checks {
		if c.want != c.got {
			t.Errorf("%s = %v, want %v (the config field was dropped)", c.field, c.got, c.want)
		}
	}

	// uploadSlots is the memory bound: what matters is the capacity, not the identity.
	if cap(h.uploadSlots) != uploadConc {
		t.Errorf("uploadSlots cap = %d, want %d", cap(h.uploadSlots), uploadConc)
	}
}

// Zero UploadConcurrency must leave uploadSlots NIL, not a zero-capacity channel: a
// channel with cap 0 blocks forever, so getting this wrong turns "unbounded" into
// "every upload waits out the budget and is shed with 503".
func TestNewLeavesUploadSlotsNilWhenUnbounded(t *testing.T) {
	h, err := New(HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h.uploadSlots != nil {
		t.Fatalf("uploadSlots = %v (cap %d), want nil; a cap-0 channel sheds every upload", h.uploadSlots, cap(h.uploadSlots))
	}
}

// /token exists only when a TokenHandler is configured. The route registration is a
// side effect of the field being set, and nothing else in the package would notice if
// New stopped doing it, so pin it here.
func TestNewRegistersTokenRouteOnlyWhenConfigured(t *testing.T) {
	res := testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true})
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)

	serve := func(t *testing.T, h *Handler) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:app:push", nil)
		req.Host = testTenantHost
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	withHandler, err := New(HandlerConfig{
		Resolver:       res,
		RegistryIssuer: iss,
		TokenRealm:     "https://merlin.example/token",
		Service:        "merlin",
		TokenHandler:   &TokenHandler{Resolver: res, Issuer: iss},
	})
	if err != nil {
		t.Fatalf("New with token handler: %v", err)
	}
	// 401, not 404: the route is registered and TokenHandler reached its
	// missing-credentials branch.
	if code := serve(t, withHandler); code != http.StatusUnauthorized {
		t.Errorf("GET /token with a TokenHandler: code = %d, want 401", code)
	}

	without, err := New(HandlerConfig{Resolver: res})
	if err != nil {
		t.Fatalf("New without token handler: %v", err)
	}
	if code := serve(t, without); code != http.StatusNotFound {
		t.Errorf("GET /token with no TokenHandler: code = %d, want 404 (route unregistered)", code)
	}
}
