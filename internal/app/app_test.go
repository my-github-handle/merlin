package app

import (
	"context"
	"testing"

	"github.com/merlin-gate/merlin/internal/config"
)

func minimalConfig() config.Config {
	return config.Config{
		Grype:     config.GrypeConfig{SeverityThreshold: "CRITICAL"},
		BaseImage: config.BaseImageConfig{AllowedIDs: []string{"rhel", "wolfi", "chainguard"}},
		ACR:       config.ACRConfig{RegistryTemplate: "{prefix}acr.azurecr.io", BaseDomain: "c3ci.cloud"},
		Auth:      config.AuthConfig{Service: "merlin"},
		Server:    config.ServerConfig{Addr: ":0", MetricsAddr: ":0"},
	}
}

func TestBuildWiresServers(t *testing.T) {
	main, metrics, err := Build(minimalConfig())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if main == nil || metrics == nil {
		t.Fatal("expected both servers wired")
	}
	if main.Handler == nil {
		t.Error("main server missing handler")
	}
}

// TestBuildWithBackendsRejectsNoTenants verifies the resolver-build path requires
// at least one configured tenant (the host->tenant security binding is empty otherwise).
func TestBuildWithBackendsRejectsNoTenants(t *testing.T) {
	cfg := prodConfig() // shared helper in app_backends_test.go
	cfg.Tenants = nil
	_, _, _, _, err := BuildWithBackends(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when no tenants configured")
	}
}
