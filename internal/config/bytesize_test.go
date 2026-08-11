package config

import (
	"strings"
	"testing"
)

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{in: "", want: 0},
		{in: "0", want: 0},
		{in: "1024", want: 1024},
		{in: "512Ki", want: 512 << 10},
		{in: "2Mi", want: 2 << 20},
		{in: "2Gi", want: 2 << 30},
		{in: " 2Gi ", want: 2 << 30},
		{in: "2gi", want: 2 << 30},
		{in: "1500m", wantErr: true}, // millicores are a CPU unit, not bytes
		{in: "2G", wantErr: true},    // decimal SI is ambiguous here; require binary
		{in: "-1", wantErr: true},
		{in: "-2Gi", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "2Gib", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseByteSize(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseByteSize(%q) = %d, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseByteSize(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseByteSize(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestGrypeMemoryLimitBytes(t *testing.T) {
	if got, err := (GrypeConfig{}).MemoryLimitBytes(); err != nil || got != 0 {
		t.Errorf("unset memory_limit = (%d, %v), want (0, nil)", got, err)
	}
	got, err := GrypeConfig{MemoryLimit: "2Gi"}.MemoryLimitBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 2<<30 {
		t.Errorf("2Gi = %d, want %d", got, int64(2<<30))
	}
}

// A malformed memory_limit must fail at startup, not at the first scan: a scan
// failure is a fail-closed push rejection, which is far more expensive to
// diagnose than a config error.
func TestLoadRejectsBadGrypeMemoryLimit(t *testing.T) {
	p := writeTemp(t, `
grype:
  severity_threshold: CRITICAL
  memory_limit: 2 gigs
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
		t.Fatal("expected error for malformed grype.memory_limit")
	}
	if !strings.Contains(err.Error(), "memory_limit") {
		t.Errorf("expected memory_limit error, got: %v", err)
	}
}

func TestLoadAcceptsGrypeMemoryLimit(t *testing.T) {
	p := writeTemp(t, `
grype:
  severity_threshold: CRITICAL
  memory_limit: 2Gi
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
	got, err := cfg.Grype.MemoryLimitBytes()
	if err != nil || got != 2<<30 {
		t.Errorf("MemoryLimitBytes() = (%d, %v), want (%d, nil)", got, err, int64(2<<30))
	}
}
