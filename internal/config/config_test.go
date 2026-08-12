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

// TestLoadAppliesSessionTTLDefault guards the staging-leak backstop against an older
// ConfigMap that predates session_ttl: an empty value must default, not silently
// become a zero TTL (which is how the Valkey key space grew unbounded).
func TestLoadAppliesSessionTTLDefault(t *testing.T) {
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
	if cfg.Staging.SessionTTL != "24h" {
		t.Errorf("default staging.session_ttl = %q, want 24h", cfg.Staging.SessionTTL)
	}
}

func TestLoadKeepsExplicitSessionTTL(t *testing.T) {
	p := writeTemp(t, `
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - { prefix: c3dev, acr_client_id: cid, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
base_image:
  allowed_ids: [rhel]
staging:
  session_ttl: 72h
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Staging.SessionTTL != "72h" {
		t.Errorf("staging.session_ttl = %q, want 72h", cfg.Staging.SessionTTL)
	}
}

// TestLoadAppliesUploadMemoryDefaults pins the two knobs that bound upload memory.
// Their PRODUCT is what matters: staging re-reads the accumulated upload on every
// chunk, so N concurrent uploads of max_upload_bytes each cost a multiple of
// N x max_upload_bytes resident. The old 1 GiB x unbounded default is what let
// concurrent pushes reach the pod memory limit and get OOMKilled.
func TestLoadAppliesUploadMemoryDefaults(t *testing.T) {
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
	if cfg.Server.MaxUploadBytes != 512<<20 {
		t.Errorf("default max_upload_bytes = %d, want %d (512 MiB)", cfg.Server.MaxUploadBytes, 512<<20)
	}
	if cfg.Server.UploadConcurrency != 4 {
		t.Errorf("default upload_concurrency = %d, want 4", cfg.Server.UploadConcurrency)
	}
}

func TestLoadKeepsExplicitUploadConcurrency(t *testing.T) {
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
  upload_concurrency: 8
  max_upload_bytes: 268435456
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.UploadConcurrency != 8 {
		t.Errorf("upload_concurrency = %d, want 8", cfg.Server.UploadConcurrency)
	}
	if cfg.Server.MaxUploadBytes != 268435456 {
		t.Errorf("max_upload_bytes = %d, want 268435456", cfg.Server.MaxUploadBytes)
	}
}

// TestLoadRejectsNegativeUploadConcurrency guards against a values typo silently
// disabling the memory bound: -1 would fall through as "no limit", which is exactly
// the unbounded behaviour this knob exists to prevent.
func TestLoadRejectsNegativeUploadConcurrency(t *testing.T) {
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
  upload_concurrency: -1
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "upload_concurrency") {
		t.Fatalf("expected upload_concurrency error, got %v", err)
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

func TestGrypeEnforceDefaultsToTrue(t *testing.T) {
	// An absent grype.enforce must gate. A missing key that silently disables the
	// vulnerability gate would be the worst possible default.
	var c Config
	c.applyDefaults()
	if c.Grype.Enforce == nil {
		t.Fatal("applyDefaults must set Grype.Enforce so the value is never ambiguous")
	}
	if !*c.Grype.Enforce {
		t.Error("grype.enforce must default to true")
	}
}

func TestGrypeEnforceFalseIsPreserved(t *testing.T) {
	// Explicit false must survive applyDefaults — the *bool exists precisely so
	// "set to false" is distinguishable from "not set".
	off := false
	c := Config{Grype: GrypeConfig{Enforce: &off}}
	c.applyDefaults()
	if c.Grype.Enforce == nil || *c.Grype.Enforce {
		t.Error("an explicit grype.enforce: false must not be overwritten by defaults")
	}
}

// minimalConfig is the smallest valid config, so an alerts test only has to state
// the alerts block it is exercising.
func minimalConfig(extra string) string {
	return `
base_image:
  allowed_ids: [rhel]
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
audit:
  clickhouse_dsn: clickhouse://ch:9000/merlin
tenants:
  - prefix: c3dev
    acr_client_id: cid
    auth:
      issuer: https://login/dev/v2.0
      audience: api://merlin-dev
      jwks_url: https://login/dev/keys
      tenant_id: dev-tenant
` + extra
}

func TestAlertsAreOffWithoutAWebhook(t *testing.T) {
	// No separate `enabled` flag: a config that says enabled but has nowhere to send
	// findings is silently useless, which is the state this whole feature exists to
	// remove. Presence of the webhook IS the switch.
	cfg, err := Load(writeTemp(t, minimalConfig("")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Alerts.Enabled() {
		t.Error("alerts enabled with no slack_webhook_url")
	}
}

func TestAlertsEnabledByWebhookAndDefaulted(t *testing.T) {
	t.Setenv("HOOK", "https://hooks.slack.com/services/T/B/xxx")
	cfg, err := Load(writeTemp(t, minimalConfig(`
alerts:
  slack_webhook_url: ${HOOK}
`)))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Alerts.Enabled() {
		t.Fatal("alerts should be enabled when a webhook is configured")
	}
	if cfg.Alerts.SlackWebhookURL != "https://hooks.slack.com/services/T/B/xxx" {
		t.Errorf("webhook not expanded from env: %q", cfg.Alerts.SlackWebhookURL)
	}
	// Durations are left to the alert package's own defaults, so an operator who sets
	// only the webhook gets the tuned windows rather than zero-valued ones.
	if cfg.Alerts.Interval != "" || cfg.Alerts.RecentWindow != "" {
		t.Errorf("config should not invent duration defaults: %+v", cfg.Alerts)
	}
}

func TestAlertsRejectUnparseableDurations(t *testing.T) {
	// Fail at startup, not on the first tick: a bad duration on a background ticker
	// would otherwise be discovered as silence.
	for _, field := range []string{"interval", "recent_window", "baseline_window", "cooldown"} {
		t.Run(field, func(t *testing.T) {
			_, err := Load(writeTemp(t, minimalConfig(`
alerts:
  slack_webhook_url: https://hooks.slack.com/x
  `+field+`: "half an hour"
`)))
			if err == nil {
				t.Fatalf("accepted an unparseable %s", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error should name the field: %v", err)
			}
		})
	}
}

func TestAlertsIgnoreDurationsWhenDisabled(t *testing.T) {
	// Validation is scoped to an enabled alerter: a commented-out webhook plus a
	// leftover typo in a window must not stop the gate from starting.
	if _, err := Load(writeTemp(t, minimalConfig(`
alerts:
  interval: "half an hour"
`))); err != nil {
		t.Errorf("a disabled alerter blocked startup: %v", err)
	}
}

func TestAlertsRequireTheAuditStore(t *testing.T) {
	// The detectors ARE audit queries. Enabled with no store, the alerter would poll
	// nothing and report no findings forever — silence indistinguishable from health.
	_, err := Load(writeTemp(t, `
base_image:
  allowed_ids: [rhel]
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - prefix: c3dev
    acr_client_id: cid
    auth:
      issuer: https://login/dev/v2.0
      audience: api://merlin-dev
      jwks_url: https://login/dev/keys
      tenant_id: dev-tenant
alerts:
  slack_webhook_url: https://hooks.slack.com/x
`))
	if err == nil {
		t.Fatal("accepted an alerter with no audit.clickhouse_dsn")
	}
	if !strings.Contains(err.Error(), "audit.clickhouse_dsn") {
		t.Errorf("error should name the missing DSN: %v", err)
	}
}

func TestAlertsRejectNonPositiveDurations(t *testing.T) {
	// "0s" parses but would make the ticker spin or the window empty.
	_, err := Load(writeTemp(t, minimalConfig(`
alerts:
  slack_webhook_url: https://hooks.slack.com/x
  cooldown: "0s"
`)))
	if err == nil {
		t.Fatal("accepted a zero cooldown")
	}
}
