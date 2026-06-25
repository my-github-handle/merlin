package acr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
