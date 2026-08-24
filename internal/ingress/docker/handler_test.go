package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/tenant"
)

type fakeAuth struct{ ok bool }

func (f fakeAuth) Validate(_ context.Context, bearer string) (auth.Identity, error) {
	if !f.ok || bearer == "" {
		return auth.Identity{}, http.ErrNoCookie
	}
	return auth.Identity{Subject: "u"}, nil
}

func TestV2BaseReturns401WhenUnauthenticated(t *testing.T) {
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: false})})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = testTenantHost
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate challenge")
	}
}

func TestV2BaseReturns200WhenAuthenticated(t *testing.T) {
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true})})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rec.Code)
	}
}

func TestManifestPathRejectsUnsupportedMethod(t *testing.T) {
	// GET/HEAD on a manifest is a docker existence check → 404 (see
	// TestManifestGetHeadReturns404NotMethodNotAllowed). A truly unsupported method
	// (e.g. DELETE) on the manifest path → 405.
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true})})
	req := httptest.NewRequest(http.MethodDelete, "/v2/repo/manifests/sha256:abc", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE to manifest path: code = %d, want 405", rec.Code)
	}
}

func TestUploadPathRejectsGET(t *testing.T) {
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true})})
	req := httptest.NewRequest(http.MethodGet, "/v2/repo/blobs/uploads/session-id", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET to upload path: code = %d, want 405", rec.Code)
	}
}

func TestV2VerifiesRegistryToken(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), RegistryIssuer: iss, TokenRealm: "https://merlin.example/token", Service: "merlin"})

	// no token -> 401 + realm points at /token
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = testTenantHost
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); !strings.Contains(wa, `realm="https://merlin.example/token"`) {
		t.Errorf("challenge realm not the /token URL: %q", wa)
	}

	// valid registry token -> 200
	tok, _, _ := iss.Mint("user@x", "repository:app:push,pull", "c3dev")
	req2 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req2.Host = testTenantHost
	req2.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("valid registry token: code = %d, want 200", rec2.Code)
	}

	// a raw (non-registry) token -> 401 (entra tokens no longer accepted on /v2/)
	req3 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req3.Host = testTenantHost
	req3.Header.Set("Authorization", "Bearer some-entra-token")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Errorf("non-registry token: code = %d, want 401", rec3.Code)
	}
}

func TestValidatedIdentityRegistryMode(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), RegistryIssuer: iss, TokenRealm: "https://merlin.example/token", Service: "merlin"})

	ten := &tenant.Tenant{Prefix: "c3dev", Registry: "myreg.azurecr.io", Authn: fakeAuth{ok: true}}
	tok, _, _ := iss.Mint("alice@x", "repository:app:push,pull", "c3dev")
	r := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	r.Host = testTenantHost
	r.Header.Set("Authorization", "Bearer "+tok)
	id, ok := h.validatedIdentity(r, ten)
	if !ok || id.Subject != "alice@x" {
		t.Errorf("registry-mode identity: ok=%v subject=%q, want true/alice@x", ok, id.Subject)
	}

	// a raw (non-registry) token must NOT yield an identity under registry auth
	r2 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	r2.Host = testTenantHost
	r2.Header.Set("Authorization", "Bearer not-a-registry-token")
	if _, ok := h.validatedIdentity(r2, ten); ok {
		t.Error("raw token must not yield identity under registry auth")
	}
}

func TestRepoFromV2Path(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/v2/", ""},                                                     // bare /v2/ → ""
		{"/v2/app/manifests/v1", "app"},                                  // manifest path
		{"/v2/foo/bar/blobs/uploads/uuid", "foo/bar"},                    // multi-level repo
		{"/v2/repo/blobs/sha256:abc", "repo"},                            // blob path
		{"/v2/deep/path/structure/manifests/tag", "deep/path/structure"}, // deep repo
		{"/v2/simple", "simple"},                                         // repo name only
		{"/v2/trailing/", "trailing"},                                    // repo with trailing slash
	}

	for _, tc := range tests {
		got := repoFromV2Path(tc.path)
		if got != tc.want {
			t.Errorf("repoFromV2Path(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestManifestGetHeadReturns404NotMethodNotAllowed(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), RegistryIssuer: iss, TokenRealm: "https://merlin.example/token", Service: "merlin"})
	tok, _, _ := iss.Mint("u@x", "", "c3dev")
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		req := httptest.NewRequest(m, "/v2/app/manifests/v1", nil)
		req.Host = testTenantHost
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s manifest: code = %d, want 404 (so docker proceeds with push)", m, rec.Code)
		}
	}
}
