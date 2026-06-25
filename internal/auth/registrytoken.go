package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RegistryTokenIssuer mints and verifies the short-lived HMAC (HS256) registry
// token Merlin hands to Docker clients after validating their Entra credential.
type RegistryTokenIssuer struct {
	secret  []byte
	service string
	ttl     time.Duration
}

// NewRegistryTokenIssuer builds an issuer. secret is the shared HMAC key (all
// replicas share it), service is the token audience + WWW-Authenticate service.
func NewRegistryTokenIssuer(secret []byte, service string, ttl time.Duration) *RegistryTokenIssuer {
	return &RegistryTokenIssuer{secret: secret, service: service, ttl: ttl}
}

type registryClaims struct {
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// Mint returns a signed registry token for subject with the granted scope.
func (i *RegistryTokenIssuer) Mint(subject, scope string) (string, int, error) {
	now := time.Now()
	claims := registryClaims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "merlin",
			Subject:   subject,
			Audience:  jwt.ClaimStrings{i.service},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(i.secret)
	if err != nil {
		return "", 0, fmt.Errorf("sign registry token: %w", err)
	}
	return signed, int(i.ttl.Seconds()), nil
}

// Verify checks the registry token's signature, issuer, audience, and expiry.
func (i *RegistryTokenIssuer) Verify(token string) (string, string, error) {
	var claims registryClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		return i.secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer("merlin"),
		jwt.WithAudience(i.service),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return "", "", fmt.Errorf("verify registry token: %w", err)
	}
	return claims.Subject, claims.Scope, nil
}
