package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ClientCredentialsValidator validates an Entra client-id/secret via the OAuth2
// client-credentials grant and returns the caller identity.
type ClientCredentialsValidator interface {
	Validate(ctx context.Context, clientID, clientSecret string) (Identity, error)
}

// EntraClientCredentials validates client credentials against Entra's token endpoint.
type EntraClientCredentials struct {
	tokenURL   string
	scope      string
	httpClient *http.Client
}

// NewEntraClientCredentials builds a validator for the given tenant + scope
// (scope is typically "<audience>/.default").
func NewEntraClientCredentials(tenantID, scope string) *EntraClientCredentials {
	return &EntraClientCredentials{
		tokenURL:   fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID),
		scope:      scope,
		httpClient: http.DefaultClient,
	}
}

func (e *EntraClientCredentials) Validate(ctx context.Context, clientID, clientSecret string) (Identity, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", e.scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, fmt.Errorf("build client-credentials request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("client-credentials request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Do NOT echo the response body — it may contain sensitive detail.
		return Identity{}, fmt.Errorf("client-credentials grant failed: status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Identity{}, fmt.Errorf("read client-credentials response: %w", err)
	}
	if err := json.Unmarshal(raw, &tr); err != nil {
		return Identity{}, fmt.Errorf("decode client-credentials response: %w", err)
	}
	if tr.AccessToken == "" {
		return Identity{}, fmt.Errorf("client-credentials grant returned no access_token")
	}
	return Identity{Subject: clientID}, nil
}
