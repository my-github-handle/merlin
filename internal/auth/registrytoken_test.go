package auth

import (
	"testing"
	"time"
)

func TestRegistryTokenRoundTrip(t *testing.T) {
	iss := NewRegistryTokenIssuer([]byte("test-secret"), "merlin", 5*time.Minute)
	tok, exp, err := iss.Mint("alice@example.com", "repository:app:push,pull", "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if exp != 300 {
		t.Errorf("expiresIn = %d, want 300", exp)
	}
	sub, scope, _, err := iss.Verify(tok)
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
	tok, _, _ := a.Mint("u", "", "")
	if _, _, _, err := b.Verify(tok); err == nil {
		t.Error("token signed with secret-a must not verify under secret-b")
	}
}

func TestRegistryTokenRejectsExpired(t *testing.T) {
	iss := NewRegistryTokenIssuer([]byte("s"), "merlin", -1*time.Minute) // already expired
	tok, _, _ := iss.Mint("u", "", "")
	if _, _, _, err := iss.Verify(tok); err == nil {
		t.Error("expired token must be rejected")
	}
}

func TestRegistryTokenRejectsTampered(t *testing.T) {
	iss := NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	tok, _, _ := iss.Mint("u", "", "")
	if _, _, _, err := iss.Verify(tok + "x"); err == nil {
		t.Error("tampered token must be rejected")
	}
}

func TestRegistryTokenRejectsWrongAudience(t *testing.T) {
	a := NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	other := NewRegistryTokenIssuer([]byte("s"), "other-service", time.Minute)
	tok, _, _ := a.Mint("u", "", "")
	if _, _, _, err := other.Verify(tok); err == nil {
		t.Error("token for aud=merlin must not verify under aud=other-service")
	}
}

func TestRegistryTokenRoundTripsPrefix(t *testing.T) {
	iss := NewRegistryTokenIssuer([]byte("secret"), "merlin", time.Minute)
	tok, _, err := iss.Mint("user1", "repository:app:push,pull", "c3prod")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	sub, scope, prefix, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if sub != "user1" || scope != "repository:app:push,pull" || prefix != "c3prod" {
		t.Errorf("got sub=%q scope=%q prefix=%q", sub, scope, prefix)
	}
}
