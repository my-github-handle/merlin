package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
)

type fakeAuth struct{ ok bool }

func (f fakeAuth) Validate(_ context.Context, bearer string) (auth.Identity, error) {
	if !f.ok || bearer == "" {
		return auth.Identity{}, http.ErrNoCookie
	}
	return auth.Identity{Subject: "u"}, nil
}

func TestV2BaseReturns401WhenUnauthenticated(t *testing.T) {
	h := NewHandler(fakeAuth{ok: false}, nil, nil, nil, "myreg.azurecr.io", nil)
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
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
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", nil)
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rec.Code)
	}
}

func TestManifestPathRejectsNonPUT(t *testing.T) {
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", nil)
	req := httptest.NewRequest(http.MethodGet, "/v2/repo/manifests/sha256:abc", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET to manifest path: code = %d, want 405", rec.Code)
	}
}

func TestUploadPathRejectsGET(t *testing.T) {
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", nil)
	req := httptest.NewRequest(http.MethodGet, "/v2/repo/blobs/uploads/session-id", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET to upload path: code = %d, want 405", rec.Code)
	}
}

func TestV2VerifiesRegistryToken(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", nil)
	h.SetRegistryAuth(iss, "https://merlin.example/token", "merlin")

	// no token -> 401 + realm points at /token
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); !strings.Contains(wa, `realm="https://merlin.example/token"`) {
		t.Errorf("challenge realm not the /token URL: %q", wa)
	}

	// valid registry token -> 200
	tok, _, _ := iss.Mint("user@x", "repository:app:push,pull")
	req2 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("valid registry token: code = %d, want 200", rec2.Code)
	}

	// a raw (non-registry) token -> 401 (entra tokens no longer accepted on /v2/)
	req3 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req3.Header.Set("Authorization", "Bearer some-entra-token")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Errorf("non-registry token: code = %d, want 401", rec3.Code)
	}
}
