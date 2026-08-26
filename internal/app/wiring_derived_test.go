package app

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/merlin-gate/merlin/internal/config"
)

// This file covers the parts of app's wiring that are DERIVED from config rather than
// dialled: pure translations, defaults, and the fail-fast branches. They need no
// backend, so they stay in the hermetic suite where a regression is caught by
// `go test ./...` rather than by a target someone has to remember to run.
//
// The wiring that needs live clients is in wiring_live_test.go (build tag
// `integration`); see mage testAppWiring.

func boolPtr(b bool) *bool { return &b }

// TestGeneratePushIDIsUniqueAndHex pins the two properties the rest of the system
// relies on. The push ID keys the audit row AND the /reports/<id> URL, so a collision
// would serve one push's findings for another's image — and a non-hex ID would break
// the URL path it is pasted into.
func TestGeneratePushIDIsUniqueAndHex(t *testing.T) {
	const n = 1000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		id := generatePushID()
		if len(id) != 32 {
			t.Fatalf("push ID %q has length %d, want 32 (16 random bytes hex-encoded)", id, len(id))
		}
		if strings.TrimLeft(id, "0123456789abcdef") != "" {
			t.Fatalf("push ID %q is not lowercase hex", id)
		}
		if seen[id] {
			t.Fatalf("push ID %q generated twice in %d draws", id, n)
		}
		seen[id] = true
	}
}

// TestImageAgeRulesPerTenantOverrides is the matrix the deployment actually depends
// on: one global default plus sparse per-tenant overrides. The subtle case is the
// PARTIAL override — a tenant that sets only Enabled must keep the default threshold,
// because the rule is built by copying the default and overwriting present fields. A
// zero-value copy instead would silently set ThresholdDays to 0, and a 0-day
// threshold rejects every image ever built.
func TestImageAgeRulesPerTenantOverrides(t *testing.T) {
	cfg := config.Config{
		ImageAge: config.ImageAgeConfig{Enabled: boolPtr(true), ThresholdDays: 60},
		Tenants: []config.TenantConfig{
			{Prefix: "inherits"},
			{Prefix: "disables", ImageAge: &config.ImageAgeConfig{Enabled: boolPtr(false)}},
			{Prefix: "tightens", ImageAge: &config.ImageAgeConfig{ThresholdDays: 7}},
			{Prefix: "both", ImageAge: &config.ImageAgeConfig{Enabled: boolPtr(false), ThresholdDays: 90}},
		},
	}

	def, per := imageAgeRules(cfg)
	if !def.Enabled || def.ThresholdDays != 60 {
		t.Errorf("default = %+v, want {Enabled:true ThresholdDays:60}", def)
	}
	if _, ok := per["inherits"]; ok {
		t.Error("a tenant with no ImageAge block must have NO per-tenant entry, so it falls through to the default")
	}
	if got := per["disables"]; got.Enabled || got.ThresholdDays != 60 {
		t.Errorf("disables = %+v, want {false 60}: overriding Enabled must not reset the inherited threshold", got)
	}
	if got := per["tightens"]; !got.Enabled || got.ThresholdDays != 7 {
		t.Errorf("tightens = %+v, want {true 7}: overriding the threshold must not reset the inherited Enabled", got)
	}
	if got := per["both"]; got.Enabled || got.ThresholdDays != 90 {
		t.Errorf("both = %+v, want {false 90}", got)
	}
}

// TestImageAgeRulesDefaultsToEnabled covers the nil-Enabled fail-safe: a config built
// in code (not parsed, so applyDefaults never ran) must gate rather than wave images
// through.
func TestImageAgeRulesDefaultsToEnabled(t *testing.T) {
	def, _ := imageAgeRules(config.Config{ImageAge: config.ImageAgeConfig{ThresholdDays: 30}})
	if !def.Enabled {
		t.Error("nil ImageAge.Enabled must default to ENABLED — an unparsed config must not silently disable the age gate")
	}
}

// TestGrypeOptionsEnforcement pins the direction each enforce value fails in. The
// observe option is what makes a Critical CVE non-blocking, so getting nil wrong here
// would publish vulnerable images from a config that never said to.
func TestGrypeOptionsEnforcement(t *testing.T) {
	// Exactly one option when enforcing, and that one is the DB-age observer: it is
	// wired unconditionally because a scan is the only moment Merlin learns the
	// scanner DB's build date. Dropping it blinds scanner_db_age_seconds, the metric
	// that says whether the gate is scanning against a stale vulnerability database.
	base := len(grypeOptions(config.Config{Grype: config.GrypeConfig{Enforce: boolPtr(true)}}, policyDeps{}))
	if base != 1 {
		t.Fatalf("enforcing options = %d, want exactly 1 (the always-present DB-age observer)", base)
	}

	for _, tc := range []struct {
		name    string
		enforce *bool
		extra   int // options beyond the always-present DB-age observer
	}{
		{"nil is enforcing (unparsed config, fail-safe)", nil, 0},
		{"explicit true is enforcing", boolPtr(true), 0},
		{"explicit false adds Observe()", boolPtr(false), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := grypeOptions(config.Config{Grype: config.GrypeConfig{Enforce: tc.enforce, SeverityThreshold: "CRITICAL"}}, policyDeps{})
			if len(got) != base+tc.extra {
				t.Errorf("option count = %d, want %d", len(got), base+tc.extra)
			}
		})
	}
}

// TestGrypeRunnerRejectsUnparseableMemoryLimit covers the fail-fast on a bad limit.
// The comment on grypeRunner says an error here means the config was built in-process
// rather than loaded from disk — this asserts it errors at all rather than silently
// running an unbounded scan, which is what caused 279 OOM kills.
func TestGrypeRunnerRejectsUnparseableMemoryLimit(t *testing.T) {
	if _, err := grypeRunner(config.Config{Grype: config.GrypeConfig{MemoryLimit: "two gigabytes"}}); err == nil {
		t.Fatal("expected an error for an unparseable memory limit: silently dropping the bound is how scans went unbounded")
	}
	r, err := grypeRunner(config.Config{Grype: config.GrypeConfig{MemoryLimit: "2Gi"}})
	if err != nil {
		t.Fatalf("valid limit: %v", err)
	}
	if r == nil {
		t.Error("valid limit returned a nil runner")
	}
}

// TestAlertEnvironmentFallsBackToHostname covers the labelling chain. One Slack
// channel serves several deployments, so an unlabelled message is nearly useless —
// hence a fallback rather than an empty string.
func TestAlertEnvironmentFallsBackToHostname(t *testing.T) {
	if got := alertEnvironment(config.AlertsConfig{Environment: "merlin-opsadmin"}); got != "merlin-opsadmin" {
		t.Errorf("configured environment = %q, want it used verbatim", got)
	}

	host, err := os.Hostname()
	got := alertEnvironment(config.AlertsConfig{})
	switch {
	case err == nil && host != "":
		if got != host {
			t.Errorf("unset environment = %q, want the hostname %q (it carries the release name as its prefix)", got, host)
		}
	default:
		if got != "merlin" {
			t.Errorf("unset environment with no hostname = %q, want the %q constant", got, "merlin")
		}
	}
}

// TestStartAlerterOffWithoutWebhook pins the "off is not an error" contract: the gate
// must start with or without an alerter. This is the deployed configuration today
// (values.opsadmin.multiacr.yaml leaves the webhook out), so a regression here would
// stop the gate from booting at all.
func TestStartAlerterOffWithoutWebhook(t *testing.T) {
	closer, err := startAlerter(context.Background(), config.Config{})
	if err != nil {
		t.Fatalf("no webhook must not be an error, got %v", err)
	}
	if closer != nil {
		t.Error("no webhook must return a nil closer, not a no-op one: the caller appends it to the cleanup list only when non-nil")
	}
}

// TestStartAlerterRejectsBadWindowsBeforeConnecting is the ordering assertion that
// matters: config translation must fail BEFORE alert.NewClickHouseStore dials, or a
// typo'd duration is reported as a connection failure. The DSN here is deliberately
// unreachable — if the error mentions it, validation ran too late.
func TestStartAlerterRejectsBadWindowsBeforeConnecting(t *testing.T) {
	cfg := config.Config{
		Alerts: config.AlertsConfig{
			SlackWebhookURL: "https://hooks.slack.example/none",
			Interval:        "15m",
			RecentWindow:    "5m", // shorter than the interval: findings fall in no window
			BaselineWindow:  "168h",
		},
		Audit: config.AuditConfig{ClickHouseDSN: "clickhouse://127.0.0.1:1/nope"},
	}

	_, err := startAlerter(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected rejection: a recent_window shorter than the interval leaves a blind gap every tick")
	}
	if !strings.Contains(err.Error(), "recent_window") {
		t.Errorf("error = %q, want it to name recent_window (a config typo must not be reported as a connection failure)", err)
	}
}

// TestBuildIsHermeticAndComplete covers Build's documented contract, which R1 must
// preserve: no live backends, and the request path still fully wired. The stub-tenant
// defaults are asserted because Build is the only caller that supplies them, so
// nothing else would notice if they went missing.
func TestBuildIsHermeticAndComplete(t *testing.T) {
	t.Run("derives the stub registry from the template", func(t *testing.T) {
		srv, err := Build(minimalConfig())
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if srv.Gate.Handler == nil || srv.Metrics.Handler == nil {
			t.Fatal("both servers need handlers")
		}
		if srv.Dashboard != nil {
			t.Error("the hermetic build must wire no dashboard")
		}
	})

	t.Run("falls back when ACR config is absent", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.ACR = config.ACRConfig{} // no template, no base domain
		if _, err := Build(cfg); err != nil {
			t.Fatalf("Build must not require ACR config — it is hermetic: %v", err)
		}
	})

	t.Run("propagates a bad memory limit", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.Grype.MemoryLimit = "not-a-size"
		if _, err := Build(cfg); err == nil {
			t.Fatal("expected the grypeRunner error to surface")
		}
	})

	t.Run("starts no alerter", func(t *testing.T) {
		// Build takes no context, so it cannot own a goroutine that anything could
		// stop — and startAlerter REQUIRES one, so the alerter is unreachable from
		// here by construction. That is the contract R1 has to keep once Build and
		// BuildWithBackends share helpers.
		//
		// Counted rather than argued from the signature: Servers.Close is now
		// non-nil for the hermetic build too (so callers never branch on it), which
		// means "there is nothing to clean up" no longer follows from the return
		// type. The goroutine census is the fact that survives that change.
		before := runtime.NumGoroutine()
		cfg := minimalConfig()
		cfg.Alerts = config.AlertsConfig{SlackWebhookURL: "https://hooks.slack.example/none"}
		srv, err := Build(cfg)
		if err != nil {
			t.Fatalf("Build must ignore alert config entirely: %v", err)
		}
		srv.Close()
		if after := runtime.NumGoroutine(); after > before {
			t.Errorf("goroutines %d -> %d: the hermetic build started background work", before, after)
		}
	})
}

// TestBuildWithBackendsRejectsBadGateTimeout covers the last validation step before
// any live client is constructed. It is separate from the required-fields table
// because it is a PARSE failure, not a presence check.
func TestBuildWithBackendsRejectsBadGateTimeout(t *testing.T) {
	cfg := prodConfig()
	cfg.Server.GateTimeout = "5 minutes"
	_, err := BuildWithBackends(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected a parse error for an invalid gate_timeout")
	}
	if !strings.Contains(err.Error(), "gate timeout") {
		t.Errorf("error = %q, want it to name the gate timeout", err)
	}
}
