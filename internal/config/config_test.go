package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidConfig(t *testing.T) {
	p := writeTemp(t, `
trivy:
  severity_threshold: CRITICAL
base_image:
  allowed_ids: [rhel, wolfi, chainguard]
acr:
  registry: myreg.azurecr.io
auth:
  issuer: https://login.microsoftonline.com/tenant/v2.0
  audience: api://merlin
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Trivy.SeverityThreshold != "CRITICAL" {
		t.Errorf("threshold = %q, want CRITICAL", cfg.Trivy.SeverityThreshold)
	}
	if len(cfg.BaseImage.AllowedIDs) != 3 {
		t.Errorf("allowed_ids = %v, want 3 entries", cfg.BaseImage.AllowedIDs)
	}
}

func TestLoadAppliesThresholdDefault(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry: myreg.azurecr.io
auth:
  issuer: https://issuer
  audience: api://merlin
base_image:
  allowed_ids: [rhel]
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Trivy.SeverityThreshold != "CRITICAL" {
		t.Errorf("default threshold = %q, want CRITICAL", cfg.Trivy.SeverityThreshold)
	}
}

func TestLoadRejectsMissingACRRegistry(t *testing.T) {
	p := writeTemp(t, `
auth:
  issuer: https://issuer
  audience: api://merlin
base_image:
  allowed_ids: [rhel]
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for missing acr.registry, got nil")
	}
	if !strings.Contains(err.Error(), "acr.registry") {
		t.Errorf("expected acr.registry error, got: %v", err)
	}
}

func TestLoadRejectsMissingAuthIssuer(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry: myreg.azurecr.io
auth:
  audience: api://merlin
base_image:
  allowed_ids: [rhel]
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for missing auth.issuer")
	}
	if !strings.Contains(err.Error(), "auth.issuer") {
		t.Errorf("expected auth.issuer error, got: %v", err)
	}
}

func TestLoadRejectsMissingAuthAudience(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry: myreg.azurecr.io
auth:
  issuer: https://issuer
base_image:
  allowed_ids: [rhel]
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for missing auth.audience")
	}
	if !strings.Contains(err.Error(), "auth.audience") {
		t.Errorf("expected auth.audience error, got: %v", err)
	}
}

func TestLoadRejectsEmptyAllowedIDs(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry: myreg.azurecr.io
auth:
  issuer: https://issuer
  audience: api://merlin
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for empty base_image.allowed_ids")
	}
	if !strings.Contains(err.Error(), "allowed_ids") {
		t.Errorf("expected allowed_ids error, got: %v", err)
	}
}

func TestLoadRejectsInvalidThreshold(t *testing.T) {
	p := writeTemp(t, `
trivy:
  severity_threshold: SUPER_CRITICAL
acr:
  registry: myreg.azurecr.io
auth:
  issuer: https://issuer
  audience: api://merlin
base_image:
  allowed_ids: [rhel]
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for invalid severity_threshold")
	}
	if !strings.Contains(err.Error(), "severity_threshold") {
		t.Errorf("expected severity_threshold error, got: %v", err)
	}
}

func TestLoadExpandsEnvVars(t *testing.T) {
	// Test case (a): config with ${VAR} expands when env var is set
	t.Setenv("TEST_CH_PW", "test_password_123")
	p := writeTemp(t, `
acr:
  registry: myreg.azurecr.io
auth:
  issuer: https://issuer
  audience: api://merlin
base_image:
  allowed_ids: [rhel]
audit:
  clickhouse_dsn: clickhouse://merlin:${TEST_CH_PW}@host:9000/merlin
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "clickhouse://merlin:test_password_123@host:9000/merlin"
	if cfg.Audit.ClickHouseDSN != want {
		t.Errorf("clickhouse_dsn = %q, want %q", cfg.Audit.ClickHouseDSN, want)
	}
}

func TestLoadRejectsUnsetEnvVar(t *testing.T) {
	// Test case (b): config referencing UNSET var returns error naming the var
	p := writeTemp(t, `
acr:
  registry: myreg.azurecr.io
auth:
  issuer: https://issuer
  audience: api://merlin
base_image:
  allowed_ids: [rhel]
audit:
  clickhouse_dsn: clickhouse://merlin:${MISSING_VAR}@host:9000/merlin
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for unset env var, got nil")
	}
	if !strings.Contains(err.Error(), "MISSING_VAR") {
		t.Errorf("expected error naming MISSING_VAR, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unset config env var") {
		t.Errorf("expected 'unset config env var' in error, got: %v", err)
	}
}

func TestLoadWithNoEnvRefsStillWorks(t *testing.T) {
	// Test case (c): config with no env refs still loads fine (regression)
	p := writeTemp(t, `
acr:
  registry: myreg.azurecr.io
auth:
  issuer: https://issuer
  audience: api://merlin
base_image:
  allowed_ids: [rhel]
audit:
  clickhouse_dsn: clickhouse://merlin:plainpassword@host:9000/merlin
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("config without env refs should load fine, got: %v", err)
	}
	want := "clickhouse://merlin:plainpassword@host:9000/merlin"
	if cfg.Audit.ClickHouseDSN != want {
		t.Errorf("clickhouse_dsn = %q, want %q", cfg.Audit.ClickHouseDSN, want)
	}
}

func TestLoadAppliesTokenEndpointDefaults(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry: r.azurecr.io
auth:
  issuer: https://issuer
  audience: api://merlin
base_image:
  allowed_ids: [rhel]
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Auth.Service != "merlin" {
		t.Errorf("Service default = %q, want merlin", cfg.Auth.Service)
	}
	if cfg.Auth.RegistryTokenTTL != "5m" {
		t.Errorf("RegistryTokenTTL default = %q, want 5m", cfg.Auth.RegistryTokenTTL)
	}
}

func TestLoadReadsTokenEndpointFields(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry: r.azurecr.io
auth:
  issuer: https://issuer
  audience: api://merlin
  tenant_id: my-tenant
  service: myreg
  registry_token_secret: shh
  registry_token_ttl: 10m
base_image:
  allowed_ids: [rhel]
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Auth.TenantID != "my-tenant" || cfg.Auth.Service != "myreg" ||
		cfg.Auth.RegistryTokenSecret != "shh" || cfg.Auth.RegistryTokenTTL != "10m" {
		t.Errorf("token fields not read: %+v", cfg.Auth)
	}
}

func TestDashboardAndRetentionDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Minimal valid config (mirrors other tests in this file): acr.registry,
	// auth.issuer, auth.audience, base_image.allowed_ids are required.
	yaml := "" +
		"acr:\n  registry: example.azurecr.io\n" +
		"auth:\n  issuer: https://issuer\n  audience: api://merlin\n" +
		"base_image:\n  allowed_ids: [\"ubi9\"]\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.DashboardAddr != "" {
		t.Errorf("DashboardAddr default = %q, want empty (disabled)", cfg.Server.DashboardAddr)
	}
	if cfg.Audit.RetentionDays != 30 {
		t.Errorf("RetentionDays default = %d, want 30", cfg.Audit.RetentionDays)
	}
}

func TestDashboardAddrParsed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "" +
		"acr:\n  registry: example.azurecr.io\n" +
		"auth:\n  issuer: https://issuer\n  audience: api://merlin\n" +
		"base_image:\n  allowed_ids: [\"ubi9\"]\n" +
		"server:\n  dashboard_addr: \":8080\"\n" +
		"audit:\n  retention_days: 7\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.DashboardAddr != ":8080" {
		t.Errorf("DashboardAddr = %q, want :8080", cfg.Server.DashboardAddr)
	}
	if cfg.Audit.RetentionDays != 7 {
		t.Errorf("RetentionDays = %d, want 7", cfg.Audit.RetentionDays)
	}
}
