package docker

import (
	"encoding/json"
	"net/http"

	"github.com/merlin-gate/merlin/internal/auth"
)

// TokenHandler implements the Docker registry token endpoint (GET /token).
// It is the SOLE Entra-validation point: it validates the inbound credential
// (Entra user token, else client-credentials) and mints a short-lived registry
// token that /v2/ verifies.
type TokenHandler struct {
	Authn       auth.Authenticator
	ClientCreds auth.ClientCredentialsValidator
	Issuer      *auth.RegistryTokenIssuer
}

func (t *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || pass == "" {
		unauthorizedToken(w)
		return
	}
	scope := r.URL.Query().Get("scope")

	// 1. Try the password as an Entra user access token.
	if id, err := t.Authn.Validate(r.Context(), pass); err == nil {
		t.issue(w, id.Subject, scope)
		return
	}
	// 2. Fall back to client-credentials (user=client-id, pass=client-secret).
	if id, err := t.ClientCreds.Validate(r.Context(), user, pass); err == nil {
		t.issue(w, id.Subject, scope)
		return
	}
	unauthorizedToken(w)
}

func (t *TokenHandler) issue(w http.ResponseWriter, subject, scope string) {
	tok, expiresIn, err := t.Issuer.Mint(subject, scope)
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
