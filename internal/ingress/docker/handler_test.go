package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
