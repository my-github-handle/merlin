package app

import (
	"context"
	"strings"
	"testing"

	"github.com/merlin-gate/merlin/internal/config"
)

// prodConfig returns a minimally complete config for production BuildWithBackends.
func prodConfig() config.Config {
	return config.Config{
		Trivy:     config.TrivyConfig{SeverityThreshold: "CRITICAL"},
		BaseImage: config.BaseImageConfig{AllowedIDs: []string{"rhel", "wolfi", "chainguard"}},
		ACR:       config.ACRConfig{Registry: "myreg.azurecr.io"},
		Auth: config.AuthConfig{
			Issuer:              "https://issuer",
			Audience:            "api://merlin",
			JWKSURL:             "https://login.microsoftonline.com/common/discovery/keys",
			TenantID:            "tenant-id",
			Service:             "merlin",
			RegistryTokenSecret: "test-secret-32-bytes-minimum!!",
			RegistryTokenTTL:    "5m",
		},
		Staging: config.StagingConfig{
			BlobAccountURL: "https://myaccount.blob.core.windows.net",
			BlobContainer:  "staging",
			ValkeyAddr:     "localhost:6379",
			ScratchDir:     "/tmp/scratch",
			ScanPoolSize:   4,
		},
		Audit: config.AuditConfig{
			ClickHouseDSN: "clickhouse://localhost:9000/default",
			QueueSize:     1024,
		},
		Server: config.ServerConfig{
			Addr:           ":5000",
			MetricsAddr:    ":9090",
			ExternalURL:    "https://merlin.example.com",
			MaxUploadBytes: 1 << 30,
			GateTimeout:    "5m",
		},
	}
}

// TestBuildWithBackends_ValidatesRequiredFields verifies that BuildWithBackends
// rejects configs missing production-required fields BEFORE attempting network calls.
// This ensures unit tests can validate config checking without hitting live backends.
func TestBuildWithBackends_ValidatesRequiredFields(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*config.Config)
		wantField string
	}{
		{
			name:      "missing JWKSURL",
			mutate:    func(c *config.Config) { c.Auth.JWKSURL = "" },
			wantField: "JWKSURL",
		},
		{
			name:      "missing BlobAccountURL",
			mutate:    func(c *config.Config) { c.Staging.BlobAccountURL = "" },
			wantField: "BlobAccountURL",
		},
		{
			name:      "missing ValkeyAddr",
			mutate:    func(c *config.Config) { c.Staging.ValkeyAddr = "" },
			wantField: "ValkeyAddr",
		},
		{
			name:      "missing ClickHouseDSN",
			mutate:    func(c *config.Config) { c.Audit.ClickHouseDSN = "" },
			wantField: "ClickHouseDSN",
		},
		{
			name:      "missing ACR.Registry",
			mutate:    func(c *config.Config) { c.ACR.Registry = "" },
			wantField: "Registry",
		},
		{
			name:      "missing RegistryTokenSecret",
			mutate:    func(c *config.Config) { c.Auth.RegistryTokenSecret = "" },
			wantField: "RegistryTokenSecret",
		},
		{
			name:      "missing ExternalURL",
			mutate:    func(c *config.Config) { c.Server.ExternalURL = "" },
			wantField: "ExternalURL",
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := prodConfig()
			tt.mutate(&cfg)

			_, _, _, err := BuildWithBackends(ctx, cfg)
			if err == nil {
				t.Fatalf("expected error for missing %s, got nil", tt.wantField)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("error %q does not mention field %q", err, tt.wantField)
			}
		})
	}
}
