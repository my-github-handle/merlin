// Package config loads and validates Merlin's startup configuration.
package config

import (
	"fmt"
	"os"

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
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	JWKSURL  string `yaml:"jwks_url"`
}

type StagingConfig struct {
	BlobConnString string `yaml:"blob_conn_string"`
	BlobContainer  string `yaml:"blob_container"`
	ValkeyAddr     string `yaml:"valkey_addr"`
	ScratchDir     string `yaml:"scratch_dir"`
	ScanPoolSize   int    `yaml:"scan_pool_size"`
}

type AuditConfig struct {
	ClickHouseDSN string `yaml:"clickhouse_dsn"`
}

type ServerConfig struct {
	Addr        string `yaml:"addr"`
	MetricsAddr string `yaml:"metrics_addr"`
}

// Load reads a YAML config file, applies defaults, and validates required fields.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
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
	if c.Server.Addr == "" {
		c.Server.Addr = ":5000"
	}
	if c.Server.MetricsAddr == "" {
		c.Server.MetricsAddr = ":9090"
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
