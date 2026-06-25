package auth

import (
	"testing"
	"time"
)

func TestRegistryTokenRoundTrip(t *testing.T) {
	iss := NewRegistryTokenIssuer([]byte("test-secret"), "merlin", 5*time.Minute)
	tok, exp, err := iss.Mint("alice@example.com", "repository:app:push,pull")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if exp != 300 {
		t.Errorf("expiresIn = %d, want 300", exp)
	}
	sub, scope, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if sub != "alice@example.com" {
		t.Errorf("sub = %q", sub)
	}
	if scope != "repository:app:push,pull" {
		t.Errorf("scope = %q", scope)
	}
}

func TestRegistryTokenRejectsWrongSecret(t *testing.T) {
	a := NewRegistryTokenIssuer([]byte("secret-a"), "merlin", time.Minute)
	b := NewRegistryTokenIssuer([]byte("secret-b"), "merlin", time.Minute)
	tok, _, _ := a.Mint("u", "")
	if _, _, err := b.Verify(tok); err == nil {
		t.Error("token signed with secret-a must not verify under secret-b")
	}
}

func TestRegistryTokenRejectsExpired(t *testing.T) {
	iss := NewRegistryTokenIssuer([]byte("s"), "merlin", -1*time.Minute) // already expired
	tok, _, _ := iss.Mint("u", "")
	if _, _, err := iss.Verify(tok); err == nil {
		t.Error("expired token must be rejected")
	}
}

func TestRegistryTokenRejectsTampered(t *testing.T) {
	iss := NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	tok, _, _ := iss.Mint("u", "")
	if _, _, err := iss.Verify(tok + "x"); err == nil {
		t.Error("tampered token must be rejected")
	}
}

func TestRegistryTokenRejectsWrongAudience(t *testing.T) {
	a := NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	other := NewRegistryTokenIssuer([]byte("s"), "other-service", time.Minute)
	tok, _, _ := a.Mint("u", "")
	if _, _, err := other.Verify(tok); err == nil {
		t.Error("token for aud=merlin must not verify under aud=other-service")
	}
}
