package acr

import "testing"

func TestNewACRPusherWithCredentialValidatesRegistry(t *testing.T) {
	if _, err := NewACRPusherWithCredential(""); err == nil {
		t.Error("expected error for empty registry")
	}
}
