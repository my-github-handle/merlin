// Package auth validates inbound Entra ID bearer tokens.
package auth

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Identity is the validated caller.
type Identity struct {
	Subject string
}

// Authenticator validates a bearer token and returns the caller identity.
type Authenticator interface {
	Validate(ctx context.Context, bearer string) (Identity, error)
}

// JWTAuthenticator validates Entra ID JWTs.
type JWTAuthenticator struct {
	issuer     string
	audience   string
	keyfunc    jwt.Keyfunc
	algorithms []string
}

// NewJWTAuthenticator builds an authenticator. In production keyfunc is backed by
// the Entra JWKS endpoint; tests inject a static key.
// Defaults to RS256 (Entra ID signing algorithm).
func NewJWTAuthenticator(issuer, audience string, keyfunc jwt.Keyfunc) *JWTAuthenticator {
	return NewJWTAuthenticatorWithAlgorithms(issuer, audience, keyfunc, []string{"RS256"})
}

// NewJWTAuthenticatorWithAlgorithms builds an authenticator with custom allowed algorithms.
// Use this for testing or non-standard JWT sources.
func NewJWTAuthenticatorWithAlgorithms(issuer, audience string, keyfunc jwt.Keyfunc, algorithms []string) *JWTAuthenticator {
	return &JWTAuthenticator{issuer: issuer, audience: audience, keyfunc: keyfunc, algorithms: algorithms}
}

func (a *JWTAuthenticator) Validate(_ context.Context, bearer string) (Identity, error) {
	if bearer == "" {
		return Identity{}, fmt.Errorf("auth: empty token")
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(bearer, claims, a.keyfunc,
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.audience),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods(a.algorithms),
	)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: invalid token: %w", err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return Identity{}, fmt.Errorf("auth: token missing sub")
	}
	return Identity{Subject: sub}, nil
}
