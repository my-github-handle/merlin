package acr

import "testing"

func TestNewACRPusherWithCredentialValidatesRegistry(t *testing.T) {
	if _, err := NewACRPusherWithCredential(""); err == nil {
		t.Error("expected error for empty registry")
	}
}

func TestNewACRPusherWithClientID_Validates(t *testing.T) {
	if _, err := NewACRPusherWithClientID("", "cid"); err == nil {
		t.Error("expected error for empty registry")
	}
	if _, err := NewACRPusherWithClientID("reg.azurecr.io", ""); err == nil {
		t.Error("expected error for empty client id")
	}
}

func TestNewACRPusherWithClientID_BuildsPusher(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "t")
	t.Setenv("AZURE_CLIENT_ID", "c")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/dev/null")
	t.Setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com/")
	p, err := NewACRPusherWithClientID("c3devacr.azurecr.io", "dev-client-id")
	if err != nil {
		t.Fatalf("build pusher: %v", err)
	}
	if p == nil {
		t.Fatal("nil pusher")
	}
}
