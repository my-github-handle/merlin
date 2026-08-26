// Package config loads and validates Merlin's startup configuration.
package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Grype     GrypeConfig     `yaml:"grype"`
	BaseImage BaseImageConfig `yaml:"base_image"`
	ImageAge  ImageAgeConfig  `yaml:"image_age"`
	ACR       ACRConfig       `yaml:"acr"`
	Tenants   []TenantConfig  `yaml:"tenants"`
	Auth      AuthConfig      `yaml:"auth"`
	Staging   StagingConfig   `yaml:"staging"`
	Audit     AuditConfig     `yaml:"audit"`
	Alerts    AlertsConfig    `yaml:"alerts"`
	Server    ServerConfig    `yaml:"server"`
}

type GrypeConfig struct {
	SeverityThreshold string `yaml:"severity_threshold"`
	// Enforce decides whether findings at/above SeverityThreshold BLOCK the push
	// or are merely recorded. Pointer so an omitted key is distinguishable from an
	// explicit false, and defaulted to true: a config typo must never silently turn
	// the vulnerability gate off. Setting it false publishes images with Critical
	// CVEs — the findings are still scanned, audited, and shown on the report, and
	// the push summary says "gate not enforcing", but nothing is stopped.
	Enforce *bool `yaml:"enforce"`
	// MemoryLimit bounds a single grype scan's memory ("2Gi", or a plain byte
	// count). Empty means unbounded, because config cannot know the pod's memory
	// limit and a wrong default breaks working deployments; the chart sets an
	// explicit budget instead. Scans run concurrently, so the worst case is
	// roughly this value times staging.scan_pool_size, and that product must fit
	// under resources.limits.memory alongside the upload budget
	// (server.max_upload_bytes x server.upload_concurrency). Enforced via
	// RLIMIT_AS plus GOMEMLIMIT on the child — see internal/limitexec for why the
	// value needs headroom over the expected peak rather than tracking it.
	MemoryLimit string `yaml:"memory_limit"`
	// ScanCache reuses a completed scan when the same manifest digest is pushed
	// again. See ScanCacheConfig.
	ScanCache ScanCacheConfig `yaml:"scan_cache"`
}

// ScanCacheConfig configures reuse of a completed scan for an identical manifest
// digest, so re-pushing the same image does not re-run grype.
//
// Enabled is a plain bool, not a pointer, precisely so its zero value is OFF. Every
// other gate knob defaults to its safe/strict setting, and for this one that is
// "don't reuse": admitting an image on the strength of an earlier scan is a change
// in what a fail-closed gate does, so it has to be an explicit per-environment
// decision rather than something a chart default switches on under every existing
// install.
type ScanCacheConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxDBAge is how old the vulnerability DB behind a cached report may be before
	// the report is discarded and the image re-scanned. It is a bound on the DB, not
	// on the entry: what makes a stored report untrustworthy is a newer CVE feed, not
	// elapsed time as such.
	//
	// Anchore rebuilds the DB daily (measured: exactly one version per day in this
	// cluster, built 06:14Z-06:40Z, with no two consecutive versions' windows
	// overlapping), so the default of one day means a report is reused at most until
	// its DB is superseded.
	MaxDBAge string `yaml:"max_db_age"`
}

// defaultScanCacheMaxDBAge matches the DB rebuild period. Kept as the literal the
// yaml would carry so a values file and a defaulted config read identically;
// grype.DefaultScanCacheMaxDBAge is where the same period is enforced on reads.
const defaultScanCacheMaxDBAge = "24h"

// maxScanCacheDBAge caps the configurable window at two rebuild periods: enough
// slack to survive one missed Anchore build, and short enough that a report can
// never be reused across two of them. Past this the cache would be admitting images
// on a superseded CVE feed, and silently — nothing else in the system reports it.
const maxScanCacheDBAge = 48 * time.Hour

// MaxDBAgeDuration parses MaxDBAge, treating an empty value as the default so a
// hand-built Config behaves like a loaded one. The same call validates at startup
// and configures the policy at wiring time, so the two cannot disagree.
func (s ScanCacheConfig) MaxDBAgeDuration() (time.Duration, error) {
	v := s.MaxDBAge
	if v == "" {
		v = defaultScanCacheMaxDBAge
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("grype.scan_cache.max_db_age %q is not a duration (e.g. 24h, 90m): %w", v, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("grype.scan_cache.max_db_age must be > 0, got %s", v)
	}
	if d > maxScanCacheDBAge {
		return 0, fmt.Errorf("grype.scan_cache.max_db_age %s exceeds the %s maximum; the vulnerability DB is rebuilt daily, so a longer window would keep admitting images on a superseded feed", v, maxScanCacheDBAge)
	}
	return d, nil
}

type BaseImageConfig struct {
	AllowedIDs []string `yaml:"allowed_ids"`
}

// ImageAgeConfig configures the image-age gate policy. Enabled is a pointer so an
// unset value can inherit the default (true) rather than defaulting to false.
type ImageAgeConfig struct {
	Enabled       *bool `yaml:"enabled"`
	ThresholdDays int   `yaml:"threshold_days"`
}

type ACRConfig struct {
	RegistryTemplate string `yaml:"registry_template"`
	BaseDomain       string `yaml:"base_domain"`
}

type TenantAuthConfig struct {
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	JWKSURL  string `yaml:"jwks_url"`
	TenantID string `yaml:"tenant_id"`
}

type TenantConfig struct {
	Prefix      string           `yaml:"prefix"`
	ACRClientID string           `yaml:"acr_client_id"`
	Auth        TenantAuthConfig `yaml:"auth"`
	ImageAge    *ImageAgeConfig  `yaml:"image_age"`
}

// Registry substitutes this tenant's prefix into the ACR host template.
func (t TenantConfig) Registry(template string) string {
	return strings.ReplaceAll(template, "{prefix}", t.Prefix)
}

type AuthConfig struct {
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
	// SessionTTL bounds how long per-push staging state lives in Valkey. It is the
	// backstop for state that explicit cleanup cannot reclaim (a SIGKILL skips
	// defers; an abandoned push never sends its manifest). Must comfortably exceed
	// the slowest real push: a push still in flight past this window loses its
	// staging state and fails with a 400, forcing the client to re-push.
	SessionTTL string `yaml:"session_ttl"`
}

type AuditConfig struct {
	ClickHouseDSN string `yaml:"clickhouse_dsn"`
	QueueSize     int    `yaml:"queue_size"`
	RetentionDays int    `yaml:"retention_days"`
}

// AlertsConfig configures the background alerter, which polls the audit table for
// infra-error patterns and posts findings to a Slack incoming webhook.
//
// There is deliberately no `enabled` flag: the webhook URL IS the switch. A config
// that says enabled but has nowhere to send findings would be silently useless,
// which is the exact failure mode this feature exists to remove. It also needs
// audit.clickhouse_dsn — with no audit store there is nothing to poll.
//
// Every duration is a string parsed with time.ParseDuration at startup (the
// server.gate_timeout convention), and left EMPTY by default so the tuned defaults
// in internal/alert are the single source of truth rather than being duplicated here.
type AlertsConfig struct {
	// SlackWebhookURL is a credential: anyone holding it can post to the channel.
	// Supply it via ${ENV} expansion from a secret, never inline in the values file.
	SlackWebhookURL string `yaml:"slack_webhook_url"`
	// Environment labels every message, because one channel usually serves several
	// deployments. Defaults to the release/pod name at wiring time if empty.
	Environment string `yaml:"environment"`
	// Interval is how often the detectors run. RecentWindow should be >= Interval or
	// findings that occur between runs fall in no window at all.
	Interval     string `yaml:"interval"`
	RecentWindow string `yaml:"recent_window"`
	// BaselineWindow is the "known signatures" history that novelty is judged against.
	// It must stay comfortably inside audit.retention_days or its older half is empty
	// and previously-seen signatures read as novel again.
	BaselineWindow string `yaml:"baseline_window"`
	// Cooldown suppresses re-announcing the same (detector, signature) class.
	Cooldown string `yaml:"cooldown"`
	// KilledScanThreshold is how many SIGKILLed scans in one recent window trigger a
	// page. Zero means the alert package's default.
	KilledScanThreshold uint64 `yaml:"killed_scan_threshold"`
	// MaxNovelPerRun caps novel-signature messages per run so a broad outage cannot
	// flood the channel. What the cap drops is logged, never silently discarded.
	MaxNovelPerRun int `yaml:"max_novel_per_run"`
}

// Enabled reports whether the alerter should be started.
func (a AlertsConfig) Enabled() bool { return a.SlackWebhookURL != "" }

// durations returns the yaml key -> value pairs for validation, so a bad duration is
// rejected at startup instead of surfacing later as a silent background ticker.
func (a AlertsConfig) durations() map[string]string {
	return map[string]string{
		"interval":        a.Interval,
		"recent_window":   a.RecentWindow,
		"baseline_window": a.BaselineWindow,
		"cooldown":        a.Cooldown,
	}
}

type ServerConfig struct {
	Addr          string `yaml:"addr"`
	MetricsAddr   string `yaml:"metrics_addr"`
	DashboardAddr string `yaml:"dashboard_addr"` // default ":8080"; set "off" to disable
	ExternalURL   string `yaml:"external_url"`
	// MaxUploadBytes caps a single blob-upload request body. Staging buffers the
	// chunk AND re-reads the accumulated upload, so resident memory per in-flight
	// upload is a multiple of this; the effective worst case is roughly this value
	// times upload_concurrency. Keep the product well under the pod memory limit.
	MaxUploadBytes int64 `yaml:"max_upload_bytes"`
	// UploadConcurrency caps how many blob uploads may buffer bytes simultaneously.
	// Excess uploads queue, then receive 503 + Retry-After. Separate from
	// staging.scan_pool_size, which bounds Grype CPU, not upload memory.
	UploadConcurrency int    `yaml:"upload_concurrency"`
	GateTimeout       string `yaml:"gate_timeout"`
	// ShutdownTimeout bounds how long the servers drain in-flight requests on
	// SIGTERM before backends are closed. It should exceed gate_timeout so a push
	// already in the gate can finish, and stay under the pod terminationGracePeriod
	// so Kubernetes does not SIGKILL mid-drain.
	ShutdownTimeout string `yaml:"shutdown_timeout"`
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
	if c.Grype.SeverityThreshold == "" {
		c.Grype.SeverityThreshold = "CRITICAL"
	}
	if c.Grype.Enforce == nil {
		enforce := true
		c.Grype.Enforce = &enforce
	}
	if c.Grype.ScanCache.MaxDBAge == "" {
		c.Grype.ScanCache.MaxDBAge = defaultScanCacheMaxDBAge
	}
	if c.ImageAge.ThresholdDays == 0 {
		c.ImageAge.ThresholdDays = 60
	}
	if c.ImageAge.Enabled == nil {
		enabled := true
		c.ImageAge.Enabled = &enabled
	}
	if c.Staging.ScanPoolSize == 0 {
		c.Staging.ScanPoolSize = 4
	}
	if c.Staging.SessionTTL == "" {
		c.Staging.SessionTTL = "24h"
	}
	if c.Audit.QueueSize == 0 {
		c.Audit.QueueSize = 1024
	}
	if c.Audit.RetentionDays == 0 {
		c.Audit.RetentionDays = 30
	}
	if c.Server.Addr == "" {
		c.Server.Addr = ":5000"
	}
	if c.Server.MetricsAddr == "" {
		c.Server.MetricsAddr = ":9090"
	}
	if c.Server.DashboardAddr == "" {
		// Dashboard is on by default. Set dashboard_addr to "off" to disable it.
		c.Server.DashboardAddr = ":8080"
	}
	if c.Server.MaxUploadBytes == 0 {
		// 512 MiB. Lowered from 1 GiB: with upload_concurrency below, the worst-case
		// resident upload memory is a multiple of the product of the two, and 1 GiB
		// chunks could not be absorbed by the memory limit merlin runs under.
		c.Server.MaxUploadBytes = 512 << 20
	}
	if c.Server.UploadConcurrency == 0 {
		c.Server.UploadConcurrency = 4
	}
	if c.Server.GateTimeout == "" {
		c.Server.GateTimeout = "5m"
	}
	if c.Server.ShutdownTimeout == "" {
		// Slightly above gate_timeout so a push already in the gate can complete its
		// drain. Pair with a pod terminationGracePeriodSeconds >= this value.
		c.Server.ShutdownTimeout = "6m"
	}
	if c.Auth.Service == "" {
		c.Auth.Service = "merlin"
	}
	if c.Auth.RegistryTokenTTL == "" {
		c.Auth.RegistryTokenTTL = "5m"
	}
}

var validSeverities = map[string]bool{
	"NEGLIGIBLE": true, "UNKNOWN": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

func (c *Config) validate() error {
	if c.ACR.RegistryTemplate == "" {
		return fmt.Errorf("config: acr.registry_template is required")
	}
	if !strings.Contains(c.ACR.RegistryTemplate, "{prefix}") {
		return fmt.Errorf("config: acr.registry_template must contain {prefix}")
	}
	if c.ACR.BaseDomain == "" {
		return fmt.Errorf("config: acr.base_domain is required")
	}
	if len(c.Tenants) == 0 {
		return fmt.Errorf("config: at least one tenant is required")
	}
	seen := make(map[string]bool, len(c.Tenants))
	for i, t := range c.Tenants {
		if t.Prefix == "" {
			return fmt.Errorf("config: tenants[%d].prefix is required", i)
		}
		if seen[t.Prefix] {
			return fmt.Errorf("config: duplicate tenant prefix %q", t.Prefix)
		}
		seen[t.Prefix] = true
		if t.ACRClientID == "" {
			return fmt.Errorf("config: tenants[%d] (%s) acr_client_id is required", i, t.Prefix)
		}
		if t.Auth.Issuer == "" || t.Auth.Audience == "" || t.Auth.JWKSURL == "" || t.Auth.TenantID == "" {
			return fmt.Errorf("config: tenants[%d] (%s) auth block requires issuer, audience, jwks_url, tenant_id", i, t.Prefix)
		}
	}
	if len(c.BaseImage.AllowedIDs) == 0 {
		return fmt.Errorf("config: base_image.allowed_ids must not be empty")
	}
	if !validSeverities[c.Grype.SeverityThreshold] {
		return fmt.Errorf("config: grype.severity_threshold %q is not a valid severity (NEGLIGIBLE, UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)", c.Grype.SeverityThreshold)
	}
	// Reject at startup: an unparseable limit would otherwise surface as a failed
	// scan, and a failed scan is a fail-closed push rejection.
	if _, err := c.Grype.MemoryLimitBytes(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if c.ImageAge.ThresholdDays < 0 {
		return fmt.Errorf("config: image_age.threshold_days must be >= 0")
	}
	// Reject rather than clamp: a negative value would disable the upload memory
	// bound entirely, which is the failure mode the knob exists to prevent.
	if c.Server.UploadConcurrency < 0 {
		return fmt.Errorf("config: server.upload_concurrency must be >= 1")
	}
	if c.Server.MaxUploadBytes < 0 {
		return fmt.Errorf("config: server.max_upload_bytes must be >= 0")
	}
	for i, t := range c.Tenants {
		if t.ImageAge != nil && t.ImageAge.ThresholdDays < 0 {
			return fmt.Errorf("config: tenants[%d] (%s) image_age.threshold_days must be >= 0", i, t.Prefix)
		}
	}
	if err := c.validateScanCache(); err != nil {
		return err
	}
	if err := c.validateAlerts(); err != nil {
		return err
	}
	return nil
}

// validateScanCache checks the scan cache's config, but ONLY when it is enabled —
// the validateAlerts convention: a leftover setting under a switched-off feature
// must not stop the gate from starting.
func (c *Config) validateScanCache() error {
	if !c.Grype.ScanCache.Enabled {
		return nil
	}
	if _, err := c.Grype.ScanCache.MaxDBAgeDuration(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	// The store is shared across replicas; without an address there is nowhere to put
	// entries. Failing here beats every pod scanning everything while the config says
	// caching is on — a silent no-op is the failure mode this check exists to remove.
	if c.Staging.ValkeyAddr == "" {
		return fmt.Errorf("config: grype.scan_cache.enabled is true but staging.valkey_addr is empty; the scan cache is shared across replicas")
	}
	return nil
}

// validateAlerts checks the alerter's config, but ONLY when it is enabled: a
// commented-out webhook plus a leftover typo in a window must not stop the gate
// from starting, because the gate is the thing that matters.
func (c *Config) validateAlerts() error {
	if !c.Alerts.Enabled() {
		return nil
	}
	// The detectors are queries over the audit table. Without it the alerter would
	// start, poll nothing, and report no findings forever — silence indistinguishable
	// from health, which is the failure this whole feature exists to remove.
	if c.Audit.ClickHouseDSN == "" {
		return fmt.Errorf("config: alerts.slack_webhook_url is set but audit.clickhouse_dsn is empty; the alerter reads the audit table")
	}
	// Sorted so the reported field is deterministic when more than one is wrong.
	keys := make([]string, 0, 4)
	for k := range c.Alerts.durations() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := c.Alerts.durations()[k]
		if v == "" {
			continue // empty means "use the alert package default"
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("config: alerts.%s %q is not a duration (e.g. 15m, 1h, 168h): %w", k, v, err)
		}
		if d <= 0 {
			return fmt.Errorf("config: alerts.%s must be > 0, got %s", k, v)
		}
	}
	if c.Alerts.MaxNovelPerRun < 0 {
		return fmt.Errorf("config: alerts.max_novel_per_run must be >= 0")
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
