package acr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/go-containerregistry/pkg/authn"
)

// acrCredAuthenticator implements go-containerregistry's authn.Authenticator
// by exchanging an AAD token (from DefaultAzureCredential) for an ACR refresh token.
type acrCredAuthenticator struct {
	registry string
	cred     *azidentity.DefaultAzureCredential

	mu           sync.Mutex
	cachedToken  string
	cachedExpiry time.Time
}

// Authorization performs the AAD→ACR token exchange. It obtains an AAD access token
// for the scope https://containerregistry.azure.net/.default, then POSTs to the
// ACR /oauth2/exchange endpoint to get an ACR refresh token, which it returns as
// an IdentityToken (go-containerregistry uses this as a bearer/OAuth token).
func (a *acrCredAuthenticator) Authorization() (*authn.AuthConfig, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Return cached token if still valid (with 1-minute buffer)
	if a.cachedToken != "" && time.Now().Before(a.cachedExpiry.Add(-time.Minute)) {
		return &authn.AuthConfig{IdentityToken: a.cachedToken}, nil
	}

	// Step 1: Get AAD access token for ACR scope
	ctx := context.Background()
	token, err := a.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://containerregistry.azure.net/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("get AAD token: %w", err)
	}

	// Step 2: Exchange AAD token for ACR refresh token
	exchangeURL := fmt.Sprintf("https://%s/oauth2/exchange", a.registry)
	reqBody := map[string]string{
		"grant_type":   "access_token",
		"service":      a.registry,
		"access_token": token.Token,
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal exchange request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("create exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("exchange failed: %s: %s", resp.Status, string(body))
	}

	var exchangeResp struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&exchangeResp); err != nil {
		return nil, fmt.Errorf("decode exchange response: %w", err)
	}

	if exchangeResp.RefreshToken == "" {
		return nil, fmt.Errorf("empty refresh token in exchange response")
	}

	// Cache the token with the AAD token's expiry
	a.cachedToken = exchangeResp.RefreshToken
	a.cachedExpiry = token.ExpiresOn

	return &authn.AuthConfig{IdentityToken: exchangeResp.RefreshToken}, nil
}
