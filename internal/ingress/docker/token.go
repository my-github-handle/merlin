package docker

import (
	"encoding/json"
	"net/http"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/tenant"
)

// TokenHandler implements the Docker registry token endpoint (GET /token).
// It is the SOLE Entra-validation point: it resolves the tenant from the request
// host, validates the inbound credential (Entra user token, else client-credentials)
// against that tenant, and mints a short-lived registry token (bound to the tenant's
// prefix) that /v2/ verifies.
type TokenHandler struct {
	Resolver    tenant.Resolver
	ClientCreds auth.ClientCredentialsValidator
	Issuer      *auth.RegistryTokenIssuer
}

func (t *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Resolve the tenant from the request host; an unknown host is a 404.
	ten, err := t.Resolver.ForHost(r.Host)
	if err != nil {
		http.Error(w, "unknown registry", http.StatusNotFound)
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || pass == "" {
		unauthorizedToken(w)
		return
	}
	scope := r.URL.Query().Get("scope")

	// 1. Try the password as an Entra user access token against the tenant's authn.
	if id, err := ten.Authn.Validate(r.Context(), pass); err == nil {
		t.issue(w, id.Subject, scope, ten.Prefix)
		return
	}
	// 2. Fall back to client-credentials (user=client-id, pass=client-secret).
	if id, err := t.ClientCreds.Validate(r.Context(), user, pass); err == nil {
		t.issue(w, id.Subject, scope, ten.Prefix)
		return
	}
	unauthorizedToken(w)
}

func (t *TokenHandler) issue(w http.ResponseWriter, subject, scope, prefix string) {
	tok, expiresIn, err := t.Issuer.Mint(subject, scope, prefix)
	if err != nil {
		http.Error(w, "token issuance failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token":        tok,
		"access_token": tok,
		"expires_in":   expiresIn,
	})
}

func unauthorizedToken(w http.ResponseWriter) {
	// No credential value is echoed.
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
