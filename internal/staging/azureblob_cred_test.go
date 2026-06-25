package staging

import "testing"

func TestNewAzureBlobStoreWithCredentialValidatesURL(t *testing.T) {
	// Empty account URL must error (don't reach the network).
	if _, err := NewAzureBlobStoreWithCredential("", "container"); err == nil {
		t.Error("expected error for empty account URL")
	}
}
