package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientCredsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("client_id") != "cid" {
			t.Errorf("client_id = %q", r.Form.Get("client_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"xyz","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()
	v := &EntraClientCredentials{tokenURL: srv.URL, scope: "api://merlin/.default", httpClient: srv.Client()}
	id, err := v.Validate(context.Background(), "cid", "secret")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if id.Subject != "cid" {
		t.Errorf("subject = %q, want cid", id.Subject)
	}
}

func TestClientCredsFailureRedactsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","secret-leak":"super-secret-xyz"}`))
	}))
	defer srv.Close()
	v := &EntraClientCredentials{tokenURL: srv.URL, scope: "s", httpClient: srv.Client()}
	_, err := v.Validate(context.Background(), "cid", "bad")
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if strings.Contains(err.Error(), "super-secret-xyz") {
		t.Errorf("error leaked response body: %v", err)
	}
}

func TestNewEntraClientCredentialsBuildsTokenURL(t *testing.T) {
	v := NewEntraClientCredentials("my-tenant", "api://merlin/.default")
	if !strings.Contains(v.tokenURL, "my-tenant") {
		t.Errorf("tokenURL = %q, want it to contain tenant", v.tokenURL)
	}
}
