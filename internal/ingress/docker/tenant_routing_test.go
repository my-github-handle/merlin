package docker

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/tenant"
)

// fakeResolver returns a fixed single tenant for the configured host prefix.
type fakeResolver struct{ t *tenant.Tenant }

func (f fakeResolver) ForHost(host string) (*tenant.Tenant, error) {
	if f.t != nil && host == f.t.Prefix+".c3ci.cloud" {
		return f.t, nil
	}
	return nil, tenant.ErrUnknownTenant
}

// anyResolver returns the same tenant for ANY host. It is used by tests that drive
// the handler through httptest.NewServer (where the request Host is 127.0.0.1:port
// and cannot be set to a prefixed name ahead of time).
type anyResolver struct{ t *tenant.Tenant }

func (a anyResolver) ForHost(string) (*tenant.Tenant, error) {
	if a.t == nil {
		return nil, tenant.ErrUnknownTenant
	}
	return a.t, nil
}

// testTenantHost is the host every existing single-tenant test routes through.
// It maps (via testResolver) to the prefix "c3dev".
const testTenantHost = "c3dev.c3ci.cloud"

// testResolver builds a single-tenant resolver (prefix "c3dev") that existing
// handler/integration tests route through. registry is the ACR host, pusher the
// per-tenant ACR pusher, and authn the inbound auth surface.
func testResolver(registry string, pusher acr.Pusher, authn auth.Authenticator) fakeResolver {
	return fakeResolver{t: &tenant.Tenant{
		Prefix:   "c3dev",
		Registry: registry,
		Pusher:   pusher,
		Authn:    authn,
	}}
}

// mustNewHandler builds a handler from cfg and fails the test if New rejects it.
//
// Every test in this package builds a handler that is coherent by construction, so
// New's error is a bug in the test rather than a case under test — the rejections
// themselves are covered in handler_config_test.go. Wrapping it here keeps ~50 call
// sites one line each instead of four.
func mustNewHandler(t *testing.T, cfg HandlerConfig) *Handler {
	t.Helper()
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New(%+v): %v", cfg, err)
	}
	return h
}

func TestUnknownHostReturns404(t *testing.T) {
	res := fakeResolver{t: &tenant.Tenant{Prefix: "c3dev", Registry: "c3devacr.azurecr.io", Authn: fakeAuth{ok: true}}}
	h := mustNewHandler(t, HandlerConfig{Resolver: res})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "c3xxx.c3ci.cloud"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", rec.Code)
	}
}

func TestCrossPrefixTokenRejected(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	res := fakeResolver{t: &tenant.Tenant{Prefix: "c3prod", Registry: "c3prodacr.azurecr.io", Authn: fakeAuth{ok: true}}}
	h := mustNewHandler(t, HandlerConfig{Resolver: res, RegistryIssuer: iss, TokenRealm: "https://merlin/token", Service: "merlin"})

	// Token minted for c3dev, presented to c3prod host.
	tok, _, _ := iss.Mint("u", "", "c3dev")
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "c3prod.c3ci.cloud"
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401 for cross-prefix token", rec.Code)
	}
}

func TestMatchingPrefixTokenAccepted(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	res := fakeResolver{t: &tenant.Tenant{Prefix: "c3prod", Registry: "c3prodacr.azurecr.io", Authn: fakeAuth{ok: true}}}
	h := mustNewHandler(t, HandlerConfig{Resolver: res, RegistryIssuer: iss, TokenRealm: "https://merlin/token", Service: "merlin"})

	tok, _, _ := iss.Mint("u", "", "c3prod")
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "c3prod.c3ci.cloud"
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rec.Code)
	}
}
