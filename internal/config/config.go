// Package config loads and validates Merlin's startup configuration.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Trivy     TrivyConfig     `yaml:"trivy"`
	BaseImage BaseImageConfig `yaml:"base_image"`
	ACR       ACRConfig       `yaml:"acr"`
	Auth      AuthConfig      `yaml:"auth"`
	Staging   StagingConfig   `yaml:"staging"`
	Audit     AuditConfig     `yaml:"audit"`
	Server    ServerConfig    `yaml:"server"`
}

type TrivyConfig struct {
	SeverityThreshold string `yaml:"severity_threshold"`
}

type BaseImageConfig struct {
	AllowedIDs []string `yaml:"allowed_ids"`
}

type ACRConfig struct {
	Registry string `yaml:"registry"`
}

type AuthConfig struct {
	Issuer              string `yaml:"issuer"`
	Audience            string `yaml:"audience"`
	JWKSURL             string `yaml:"jwks_url"`
	TenantID            string `yaml:"tenant_id"`
	Service             string `yaml:"service"`
	RegistryTokenSecret string `yaml:"registry_token_secret"`
	RegistryTokenTTL    string `yaml:"registry_token_ttl"`
}

type StagingConfig struct {
	BlobConnString string `yaml:"blob_conn_string"`
	BlobAccountURL string `yaml:"blob_account_url"`
	BlobContainer  string `yaml:"blob_container"`
	ValkeyAddr     string `yaml:"valkey_addr"`
	ScratchDir     string `yaml:"scratch_dir"`
	ScanPoolSize   int    `yaml:"scan_pool_size"`
}

type AuditConfig struct {
	ClickHouseDSN string `yaml:"clickhouse_dsn"`
	QueueSize     int    `yaml:"queue_size"`
}

type ServerConfig struct {
	Addr           string `yaml:"addr"`
	MetricsAddr    string `yaml:"metrics_addr"`
	ExternalURL    string `yaml:"external_url"`
	MaxUploadBytes int64  `yaml:"max_upload_bytes"`
	GateTimeout    string `yaml:"gate_timeout"`
}

// Load reads a YAML config file, applies defaults, and validates required fields.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	expanded, err := expandEnvStrict(string(raw))
	if err != nil {
		return Config{}, fmt.Errorf("expand config env: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Trivy.SeverityThreshold == "" {
		c.Trivy.SeverityThreshold = "CRITICAL"
	}
	if c.Staging.ScanPoolSize == 0 {
		c.Staging.ScanPoolSize = 4
	}
	if c.Audit.QueueSize == 0 {
		c.Audit.QueueSize = 1024
	}
	if c.Server.Addr == "" {
		c.Server.Addr = ":5000"
	}
	if c.Server.MetricsAddr == "" {
		c.Server.MetricsAddr = ":9090"
	}
	if c.Server.MaxUploadBytes == 0 {
		c.Server.MaxUploadBytes = 1 << 30 // 1 GiB default
	}
	if c.Server.GateTimeout == "" {
		c.Server.GateTimeout = "5m"
	}
	if c.Auth.Service == "" {
		c.Auth.Service = "merlin"
	}
	if c.Auth.RegistryTokenTTL == "" {
		c.Auth.RegistryTokenTTL = "5m"
	}
}

var validSeverities = map[string]bool{
	"UNKNOWN": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

func (c *Config) validate() error {
	if c.ACR.Registry == "" {
		return fmt.Errorf("config: acr.registry is required")
	}
	if c.Auth.Issuer == "" {
		return fmt.Errorf("config: auth.issuer is required")
	}
	if c.Auth.Audience == "" {
		return fmt.Errorf("config: auth.audience is required")
	}
	if len(c.BaseImage.AllowedIDs) == 0 {
		return fmt.Errorf("config: base_image.allowed_ids must not be empty")
	}
	if !validSeverities[c.Trivy.SeverityThreshold] {
		return fmt.Errorf("config: trivy.severity_threshold %q is not a valid severity (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)", c.Trivy.SeverityThreshold)
	}
	return nil
}

// expandEnvStrict replaces ${VAR}/$VAR with os.Getenv(VAR), erroring if any
// referenced variable is unset (so a missing secret fails fast, not silently).
func expandEnvStrict(s string) (string, error) {
	var missing []string
	out := os.Expand(s, func(key string) string {
		v, ok := os.LookupEnv(key)
		if !ok {
			missing = append(missing, key)
			return ""
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("unset config env var(s): %s", strings.Join(missing, ", "))
	}
	return out, nil
}
