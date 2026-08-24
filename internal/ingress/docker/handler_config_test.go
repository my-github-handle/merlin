package docker

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
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

// New must produce the SAME handler the eleven setters produced.
//
// This is the whole behaviour-preservation claim of the change, stated field by
// field: anything either path writes, both paths must write identically. It exists
// only for the transition — when NewHandler and the Set* methods are deleted, this
// test goes with them.
func TestNewMatchesTheSettersItReplaces(t *testing.T) {
	// One value per field, all distinct from the zero value so a dropped assignment
	// shows up as a mismatch rather than as two matching zeroes.
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

	old := NewHandler(res, st, rt, out, reports)
	old.SetRequestObserver(requests)
	old.SetPromoter(promoter)
	old.SetMaxPendingPromotions(maxPending)
	old.SetMaxUploadBytes(maxUploadBytes)
	old.SetUploadConcurrency(uploadConc)
	old.SetUploadWait(uploadWait)
	old.SetPool(pool)
	old.SetGateTimeout(gateTimeout)
	old.SetScratchBaseDir(scratchDir)
	old.SetRegistryAuth(iss, realm, service)
	old.SetTokenHandler(tokenHdlr)

	got, err := New(HandlerConfig{
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

	// A field added to Handler and wired by only one of the two paths is exactly the
	// bug this test cannot otherwise see, because the comparison below is written out
	// by hand (reflect cannot read unexported fields). Fail loudly instead.
	if n := reflect.TypeOf(Handler{}).NumField(); n != 21 {
		t.Fatalf("Handler has %d fields, not 21: add it to New, to the comparison below, or to the skip list", n)
	}

	// mux is deliberately not compared (distinct instances by construction); the
	// routes it carries are covered by TestNewRegistersTokenRouteOnlyWhenConfigured
	// and by every other test in this package that serves /v2/ and /reports/.
	// indexWait/indexPoll are set by neither path — they are in-package test knobs.
	checks := []struct {
		field    string
		old, got any
	}{
		{"resolver", old.resolver, got.resolver},
		{"store", old.store, got.store},
		{"router", old.router, got.router},
		{"outcome", old.outcome, got.outcome},
		{"reports", old.reports, got.reports},
		{"requests", old.requests, got.requests},
		{"promoter", old.promoter, got.promoter},
		{"maxPending", old.maxPending, got.maxPending},
		{"maxUploadBytes", old.maxUploadBytes, got.maxUploadBytes},
		{"uploadWait", old.uploadWait, got.uploadWait},
		{"pool", old.pool, got.pool},
		{"gateTimeout", old.gateTimeout, got.gateTimeout},
		{"scratchBaseDir", old.scratchBaseDir, got.scratchBaseDir},
		{"regIssuer", old.regIssuer, got.regIssuer},
		{"tokenRealm", old.tokenRealm, got.tokenRealm},
		{"service", old.service, got.service},
		{"tokenHandler", old.tokenHandler, got.tokenHandler},
		{"indexWait", old.indexWait, got.indexWait},
		{"indexPoll", old.indexPoll, got.indexPoll},
	}
	for _, c := range checks {
		if c.old != c.got {
			t.Errorf("%s: setters gave %v, config gave %v", c.field, c.old, c.got)
		}
	}

	// uploadSlots is a channel: two distinct instances by construction, so compare
	// what actually governs behaviour — the capacity, which is the memory bound.
	if cap(old.uploadSlots) != cap(got.uploadSlots) {
		t.Errorf("uploadSlots cap: setters gave %d, config gave %d", cap(old.uploadSlots), cap(got.uploadSlots))
	}
	if (old.uploadSlots == nil) != (got.uploadSlots == nil) {
		t.Errorf("uploadSlots nil-ness differs: setters %v, config %v", old.uploadSlots == nil, got.uploadSlots == nil)
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

// /token exists only when a TokenHandler is configured. Under the setters the route
// was registered as a side effect of SetTokenHandler, so this pins the equivalent
// behaviour to the field.
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
