package auth

import (
	"context"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// NewEntraKeyfunc builds a JWKS-backed keyfunc for Entra ID RS256 validation.
// jwksURL is the tenant JWKS endpoint (keys auto-refresh).
func NewEntraKeyfunc(ctx context.Context, jwksURL string) (jwt.Keyfunc, error) {
	if jwksURL == "" {
		return nil, fmt.Errorf("auth: jwks URL is required")
	}
	k, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("auth: build jwks keyfunc: %w", err)
	}
	return k.Keyfunc, nil
}
