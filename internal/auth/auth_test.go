package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testKey = []byte("test-secret-key")

func signed(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testKeyfunc(*jwt.Token) (interface{}, error) { return testKey, nil }

func newAuth() *JWTAuthenticator {
	return NewJWTAuthenticatorWithAlgorithms("https://issuer", "api://merlin", testKeyfunc, []string{"HS256"})
}

func TestValidateAcceptsGoodToken(t *testing.T) {
	tok := signed(t, jwt.MapClaims{
		"iss": "https://issuer",
		"aud": "api://merlin",
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	id, err := newAuth().Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Subject != "user-123" {
		t.Errorf("subject = %q", id.Subject)
	}
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	tok := signed(t, jwt.MapClaims{
		"iss": "https://issuer", "aud": "api://other",
		"sub": "u", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := newAuth().Validate(context.Background(), tok); err == nil {
		t.Error("expected wrong-audience rejection")
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	tok := signed(t, jwt.MapClaims{
		"iss": "https://issuer", "aud": "api://merlin",
		"sub": "u", "exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := newAuth().Validate(context.Background(), tok); err == nil {
		t.Error("expected expired rejection")
	}
}

func TestValidateRejectsEmpty(t *testing.T) {
	if _, err := newAuth().Validate(context.Background(), ""); err == nil {
		t.Error("expected empty-token rejection")
	}
}

func TestValidateRejectsAlgorithmConfusion(t *testing.T) {
	// Token signed with HS256, but a default (RS256-only) authenticator must reject it,
	// regardless of the keyfunc, because the algorithm is not allowed.
	tok := signed(t, jwt.MapClaims{
		"iss": "https://issuer", "aud": "api://merlin",
		"sub": "u", "exp": time.Now().Add(time.Hour).Unix(),
	})
	a := NewJWTAuthenticator("https://issuer", "api://merlin", testKeyfunc)
	if _, err := a.Validate(context.Background(), tok); err == nil {
		t.Error("HS256 token must be rejected by an RS256-only authenticator (algorithm confusion)")
	}
}

func TestValidateRejectsWrongIssuer(t *testing.T) {
	tok := signed(t, jwt.MapClaims{
		"iss": "https://evil", "aud": "api://merlin",
		"sub": "u", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := newAuth().Validate(context.Background(), tok); err == nil {
		t.Error("expected wrong-issuer rejection")
	}
}
