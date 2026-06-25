package acr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

	// Overridable for testing
	exchangeURL string
	httpClient  *http.Client

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
	refreshToken, err := a.exchange(ctx, token.Token)
	if err != nil {
		return nil, err
	}

	// Cache the token with the AAD token's expiry
	a.cachedToken = refreshToken
	a.cachedExpiry = token.ExpiresOn

	return &authn.AuthConfig{IdentityToken: refreshToken}, nil
}

// exchange performs the ACR token exchange with form encoding (FIX 1),
// redacts error messages (FIX 2), and drains the response body (FIX 3).
func (a *acrCredAuthenticator) exchange(ctx context.Context, aadToken string) (string, error) {
	// Default to real ACR exchange URL if not set
	exchangeURL := a.exchangeURL
	if exchangeURL == "" {
		exchangeURL = fmt.Sprintf("https://%s/oauth2/exchange", a.registry)
	}

	// FIX 1: Use form encoding, not JSON
	form := url.Values{}
	form.Set("grant_type", "access_token")
	form.Set("service", a.registry)
	form.Set("access_token", aadToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		exchangeURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build acr exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := a.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("acr exchange request: %w", err)
	}

	// FIX 3: Drain body on defer so HTTP keep-alive connections are reused
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// FIX 2: Do not leak response body into error messages
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("acr token exchange failed: status %d", resp.StatusCode)
	}

	// FIX 3: Read body once into buffer, then unmarshal
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap 1MiB
	if err != nil {
		return "", fmt.Errorf("read acr exchange response: %w", err)
	}

	var exchangeResp struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(raw, &exchangeResp); err != nil {
		return "", fmt.Errorf("decode acr exchange response: %w", err)
	}

	if exchangeResp.RefreshToken == "" {
		return "", fmt.Errorf("acr token exchange returned empty refresh_token")
	}

	return exchangeResp.RefreshToken, nil
}
