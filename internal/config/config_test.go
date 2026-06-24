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
