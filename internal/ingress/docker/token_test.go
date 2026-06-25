package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
)

type stubAuthn struct{ ok bool }

func (s stubAuthn) Validate(_ context.Context, bearer string) (auth.Identity, error) {
	if s.ok && bearer == "good-entra-token" {
		return auth.Identity{Subject: "user@x"}, nil
	}
	return auth.Identity{}, errors.New("invalid")
}

type stubClientCreds struct{ ok bool }

func (s stubClientCreds) Validate(_ context.Context, id, secret string) (auth.Identity, error) {
	if s.ok && id == "cid" && secret == "csecret" {
		return auth.Identity{Subject: "cid"}, nil
	}
	return auth.Identity{}, errors.New("bad creds")
}

func basic(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

func newTokenHandler(authnOK, ccOK bool) *TokenHandler {
	return &TokenHandler{
		Authn:       stubAuthn{ok: authnOK},
		ClientCreds: stubClientCreds{ok: ccOK},
		Issuer:      auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute),
	}
}

func TestTokenEntraUserTokenSucceeds(t *testing.T) {
	h := newTokenHandler(true, false)
	req := httptest.NewRequest(http.MethodGet, "/token?service=merlin&scope=repository:app:push,pull", nil)
	req.Header.Set("Authorization", basic("ignored", "good-entra-token"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var body struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token == "" || body.ExpiresIn == 0 {
		t.Errorf("bad token body: %+v", body)
	}
	// the minted token must verify
	if _, _, err := h.Issuer.Verify(body.Token); err != nil {
		t.Errorf("minted token does not verify: %v", err)
	}
}

func TestTokenFallsBackToClientCreds(t *testing.T) {
	h := newTokenHandler(false, true) // entra fails, client-creds ok
	req := httptest.NewRequest(http.MethodGet, "/token?service=merlin", nil)
	req.Header.Set("Authorization", basic("cid", "csecret"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (client-creds fallback)", rec.Code)
	}
}

func TestTokenBothFailReturns401(t *testing.T) {
	h := newTokenHandler(false, false)
	req := httptest.NewRequest(http.MethodGet, "/token?service=merlin", nil)
	req.Header.Set("Authorization", basic("cid", "wrong"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rec.Code)
	}
}

func TestTokenMissingBasicReturns401(t *testing.T) {
	h := newTokenHandler(true, true)
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rec.Code)
	}
}

func TestTokenEmptyPasswordReturns401(t *testing.T) {
	// Empty Basic password: not a valid Entra token, and an empty client secret
	// must not authenticate -> 401 (fail closed). Even with both validators "ok",
	// the empty credential must be rejected.
	h := newTokenHandler(true, true)
	req := httptest.NewRequest(http.MethodGet, "/token?service=merlin", nil)
	req.Header.Set("Authorization", basic("cid", ""))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("empty password: code = %d, want 401 (fail closed)", rec.Code)
	}
}
