package acr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// fakeTokenCredential returns a static AAD access token with a controllable
// expiry, standing in for DefaultAzureCredential/WorkloadIdentityCredential.
type fakeTokenCredential struct {
	token     string
	expiresOn time.Time
}

func (f *fakeTokenCredential) GetToken(context.Context, azpolicy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: f.token, ExpiresOn: f.expiresOn}, nil
}

// makeRefreshToken builds a minimal unsigned JWT (header.payload.sig) whose exp
// claim is at the given time — mimicking an ACR refresh token, which is a JWT.
func makeRefreshToken(exp time.Time) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "none", "typ": "JWT"})
	payload := enc(map[string]any{"exp": exp.Unix()})
	return header + "." + payload + ".sig"
}

// TestAuthorizationReExchangesWhenRefreshTokenExpires is the regression test for
// the cache bug: the cache expiry MUST track the ACR refresh token's own exp, not
// the AAD access token's ExpiresOn. Here the AAD token is valid for 24h but each
// minted refresh token expires in ~2h; after the refresh token expires the
// authenticator MUST re-exchange (not return the stale refresh token), or leg 2
// (/oauth2/token) 401s. Reproduces the c3devops CI 502s.
func TestAuthorizationReExchangesWhenRefreshTokenExpires(t *testing.T) {
	now := time.Now()
	// AAD access token valid far into the future (the buggy cache keyed off this).
	cred := &fakeTokenCredential{token: "aad-access-token", expiresOn: now.Add(24 * time.Hour)}

	var mu sync.Mutex
	var exchangeCount int
	// Each exchange mints a refresh token that expires in 2h (shorter than the AAD token).
	refreshExp := now.Add(2 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		exchangeCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"refresh_token": %q}`, makeRefreshToken(refreshExp))
	}))
	defer srv.Close()

	auth := &acrCredAuthenticator{
		registry:    "test.azurecr.io",
		cred:        cred,
		exchangeURL: srv.URL,
		httpClient:  srv.Client(),
		nowFn:       func() time.Time { return now },
	}

	// First call: exchanges once, caches.
	if _, err := auth.Authorization(); err != nil {
		t.Fatalf("first Authorization: %v", err)
	}
	// Advance past the refresh token's exp (but still within the AAD token's 24h).
	now = now.Add(3 * time.Hour)
	if _, err := auth.Authorization(); err != nil {
		t.Fatalf("second Authorization: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if exchangeCount != 2 {
		t.Fatalf("expected re-exchange after refresh-token expiry: got %d exchanges, want 2 "+
			"(cache keyed off AAD token expiry instead of refresh-token exp?)", exchangeCount)
	}
}

// TestAuthorizationCachesWithinRefreshTokenValidity verifies the cache IS used
// while the refresh token is still valid — a second call within its exp does not
// re-exchange.
func TestAuthorizationCachesWithinRefreshTokenValidity(t *testing.T) {
	now := time.Now()
	cred := &fakeTokenCredential{token: "aad-access-token", expiresOn: now.Add(24 * time.Hour)}

	var mu sync.Mutex
	var exchangeCount int
	refreshExp := now.Add(3 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		exchangeCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"refresh_token": %q}`, makeRefreshToken(refreshExp))
	}))
	defer srv.Close()

	auth := &acrCredAuthenticator{
		registry:    "test.azurecr.io",
		cred:        cred,
		exchangeURL: srv.URL,
		httpClient:  srv.Client(),
		nowFn:       func() time.Time { return now },
	}

	if _, err := auth.Authorization(); err != nil {
		t.Fatalf("first Authorization: %v", err)
	}
	// Advance only 1h — still within the refresh token's 3h validity.
	now = now.Add(1 * time.Hour)
	if _, err := auth.Authorization(); err != nil {
		t.Fatalf("second Authorization: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if exchangeCount != 1 {
		t.Fatalf("expected cached token reuse within validity: got %d exchanges, want 1", exchangeCount)
	}
}

// TestRefreshTokenExpiry covers the JWT exp extraction helper directly.
func TestRefreshTokenExpiry(t *testing.T) {
	want := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	exp, ok := refreshTokenExpiry(makeRefreshToken(want))
	if !ok || !exp.Equal(want) {
		t.Fatalf("valid JWT: got (%v, %v), want (%v, true)", exp, ok, want)
	}
	for _, bad := range []string{"", "not.a.jwt.token", "onlyonepart", "a.b", "a.!!!.c"} {
		if _, ok := refreshTokenExpiry(bad); ok {
			t.Errorf("expected ok=false for unparseable token %q", bad)
		}
	}
}

// TestExchangeRedactsErrorBody verifies that when the ACR token exchange fails,
// the error does NOT leak the response body (which might contain sensitive tokens).
func TestExchangeRedactsErrorBody(t *testing.T) {
	const fakeSecret = "secret-token-xyz"

	// Create a fake ACR exchange endpoint that returns 400 with a secret in the body
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request is form-encoded (FIX 1 check)
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("wrong content type: got %q, want application/x-www-form-urlencoded", ct)
		}

		// Return error response with a fake secret
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant", "secret": "` + fakeSecret + `"}`))
	}))
	defer srv.Close()

	// Create authenticator with injected httptest server
	auth := &acrCredAuthenticator{
		registry:    "test.azurecr.io",
		exchangeURL: srv.URL,
		httpClient:  srv.Client(),
	}

	// Call exchange with a fake AAD token
	_, err := auth.exchange(context.Background(), "fake-aad-token")

	// Assert: (a) exchange returns an error
	if err == nil {
		t.Fatal("expected exchange to return error, got nil")
	}

	// Assert: (b) error message does NOT contain the fake secret
	errMsg := err.Error()
	if strings.Contains(errMsg, fakeSecret) {
		t.Errorf("error message leaked response body secret: %q", errMsg)
	}

	// Assert: error message contains status code (FIX 2 check)
	if !strings.Contains(errMsg, "400") && !strings.Contains(errMsg, "status") {
		t.Errorf("error message should include status code, got: %q", errMsg)
	}
}

// TestExchangeFormEncoding verifies that the exchange request uses form encoding.
func TestExchangeFormEncoding(t *testing.T) {
	receivedContentType := ""

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		// Return valid response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"refresh_token": "test-refresh-token"}`))
	}))
	defer srv.Close()

	auth := &acrCredAuthenticator{
		registry:    "test.azurecr.io",
		exchangeURL: srv.URL,
		httpClient:  srv.Client(),
	}

	_, err := auth.exchange(context.Background(), "fake-aad-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("wrong content type: got %q, want application/x-www-form-urlencoded", receivedContentType)
	}
}

// TestExchangeSuccess verifies successful token exchange with proper body draining.
func TestExchangeSuccess(t *testing.T) {
	const expectedToken = "valid-refresh-token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"refresh_token": "` + expectedToken + `"}`))
	}))
	defer srv.Close()

	auth := &acrCredAuthenticator{
		registry:    "test.azurecr.io",
		exchangeURL: srv.URL,
		httpClient:  srv.Client(),
	}

	token, err := auth.exchange(context.Background(), "fake-aad-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != expectedToken {
		t.Errorf("got token %q, want %q", token, expectedToken)
	}
}

// TestExchangeEmptyRefreshToken verifies that empty refresh_token is rejected.
func TestExchangeEmptyRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"refresh_token": ""}`))
	}))
	defer srv.Close()

	auth := &acrCredAuthenticator{
		registry:    "test.azurecr.io",
		exchangeURL: srv.URL,
		httpClient:  srv.Client(),
	}

	_, err := auth.exchange(context.Background(), "fake-aad-token")
	if err == nil {
		t.Fatal("expected error for empty refresh_token, got nil")
	}

	if !strings.Contains(err.Error(), "empty refresh_token") {
		t.Errorf("error should mention empty refresh_token, got: %v", err)
	}
}
