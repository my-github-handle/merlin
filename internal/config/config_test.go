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

func TestLoadMultiTenantConfig(t *testing.T) {
	t.Setenv("DEV_CID", "dev-client-id")
	t.Setenv("PROD_CID", "prod-client-id")
	p := writeTemp(t, `
grype:
  severity_threshold: CRITICAL
base_image:
  allowed_ids: [rhel]
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - prefix: c3dev
    acr_client_id: ${DEV_CID}
    auth:
      issuer: https://login/dev/v2.0
      audience: api://merlin-dev
      jwks_url: https://login/dev/keys
      tenant_id: dev-tenant
  - prefix: c3prod
    acr_client_id: ${PROD_CID}
    auth:
      issuer: https://login/prod/v2.0
      audience: api://merlin-prod
      jwks_url: https://login/prod/keys
      tenant_id: prod-tenant
auth:
  registry_token_secret: shh
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Tenants) != 2 {
		t.Fatalf("tenants = %d, want 2", len(cfg.Tenants))
	}
	if got := cfg.Tenants[0].Registry(cfg.ACR.RegistryTemplate); got != "c3devacr.azurecr.io" {
		t.Errorf("registry = %q, want c3devacr.azurecr.io", got)
	}
	if cfg.Tenants[0].ACRClientID != "dev-client-id" {
		t.Errorf("client id not expanded: %q", cfg.Tenants[0].ACRClientID)
	}
}

func TestLoadRejectsDuplicatePrefix(t *testing.T) {
	p := writeTemp(t, `
base_image: { allowed_ids: [rhel] }
acr: { registry_template: "{prefix}acr.azurecr.io", base_domain: c3ci.cloud }
tenants:
  - { prefix: c3dev, acr_client_id: a, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
  - { prefix: c3dev, acr_client_id: b, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate prefix error, got %v", err)
	}
}

func TestLoadRejectsTemplateWithoutPlaceholder(t *testing.T) {
	p := writeTemp(t, `
base_image: { allowed_ids: [rhel] }
acr: { registry_template: "static.azurecr.io", base_domain: c3ci.cloud }
tenants:
  - { prefix: c3dev, acr_client_id: a, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "{prefix}") {
		t.Fatalf("expected template placeholder error, got %v", err)
	}
}

func TestLoadRejectsTenantMissingClientID(t *testing.T) {
	p := writeTemp(t, `
base_image: { allowed_ids: [rhel] }
acr: { registry_template: "{prefix}acr.azurecr.io", base_domain: c3ci.cloud }
tenants:
  - { prefix: c3dev, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "acr_client_id") {
		t.Fatalf("expected acr_client_id error, got %v", err)
	}
}

func TestLoadRejectsEmptyTenants(t *testing.T) {
	p := writeTemp(t, `
base_image: { allowed_ids: [rhel] }
acr: { registry_template: "{prefix}acr.azurecr.io", base_domain: c3ci.cloud }
auth: { registry_token_secret: shh }
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "at least one tenant") {
		t.Fatalf("expected empty tenants error, got %v", err)
	}
}

func TestLoadAppliesThresholdDefault(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
base_image:
  allowed_ids: [rhel]
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Grype.SeverityThreshold != "CRITICAL" {
		t.Errorf("default threshold = %q, want CRITICAL", cfg.Grype.SeverityThreshold)
	}
}

func TestLoadAppliesShutdownTimeoutDefault(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
base_image:
  allowed_ids: [rhel]
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.ShutdownTimeout != "6m" {
		t.Errorf("default shutdown_timeout = %q, want 6m", cfg.Server.ShutdownTimeout)
	}
}

func TestLoadKeepsExplicitShutdownTimeout(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
base_image:
  allowed_ids: [rhel]
server:
  shutdown_timeout: 90s
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.ShutdownTimeout != "90s" {
		t.Errorf("shutdown_timeout = %q, want 90s", cfg.Server.ShutdownTimeout)
	}
}

func TestLoadRejectsEmptyAllowedIDs(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
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
grype:
  severity_threshold: SUPER_CRITICAL
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
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
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
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
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
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
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
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
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
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
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: my-tenant } }
auth:
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
	if cfg.Auth.Service != "myreg" ||
		cfg.Auth.RegistryTokenSecret != "shh" || cfg.Auth.RegistryTokenTTL != "10m" {
		t.Errorf("token fields not read: %+v", cfg.Auth)
	}
	// TenantID is now per-tenant
	if cfg.Tenants[0].Auth.TenantID != "my-tenant" {
		t.Errorf("tenant_id not read from tenant auth: %+v", cfg.Tenants[0].Auth)
	}
}

func TestDashboardAndRetentionDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Minimal valid config: acr with template + base_domain, tenants, base_image.allowed_ids
	yaml := "" +
		"acr:\n  registry_template: \"{prefix}acr.azurecr.io\"\n  base_domain: c3ci.cloud\n" +
		"tenants:\n  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }\n" +
		"auth: { registry_token_secret: shh }\n" +
		"base_image:\n  allowed_ids: [\"ubi9\"]\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.DashboardAddr != ":8080" {
		t.Errorf("DashboardAddr default = %q, want :8080 (on by default)", cfg.Server.DashboardAddr)
	}
	if cfg.Audit.RetentionDays != 30 {
		t.Errorf("RetentionDays default = %d, want 30", cfg.Audit.RetentionDays)
	}
}

func TestDashboardAddrOffPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// "off" is the explicit disable sentinel; applyDefaults must NOT override it.
	yaml := "" +
		"acr:\n  registry_template: \"{prefix}acr.azurecr.io\"\n  base_domain: c3ci.cloud\n" +
		"tenants:\n  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }\n" +
		"auth: { registry_token_secret: shh }\n" +
		"base_image:\n  allowed_ids: [\"ubi9\"]\n" +
		"server:\n  dashboard_addr: \"off\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.DashboardAddr != "off" {
		t.Errorf("DashboardAddr = %q, want \"off\" (explicit disable preserved)", cfg.Server.DashboardAddr)
	}
}

func TestDashboardAddrParsed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "" +
		"acr:\n  registry_template: \"{prefix}acr.azurecr.io\"\n  base_domain: c3ci.cloud\n" +
		"tenants:\n  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }\n" +
		"auth: { registry_token_secret: shh }\n" +
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

func TestImageAgeDefaults(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
base_image:
  allowed_ids: [rhel]
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ImageAge.ThresholdDays != 60 {
		t.Fatalf("default threshold = %d, want 60", cfg.ImageAge.ThresholdDays)
	}
	if cfg.ImageAge.Enabled == nil || !*cfg.ImageAge.Enabled {
		t.Fatalf("default enabled = %v, want true", cfg.ImageAge.Enabled)
	}
}

func TestImageAgeNegativeThresholdRejected(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
base_image:
  allowed_ids: [rhel]
image_age:
  threshold_days: -1
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for negative threshold")
	}
	if !strings.Contains(err.Error(), "threshold_days") {
		t.Errorf("expected threshold_days in error, got: %v", err)
	}
}
