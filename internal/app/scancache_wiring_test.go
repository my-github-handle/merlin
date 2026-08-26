package app

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/config"
	"github.com/merlin-gate/merlin/internal/policies/grype"
	"github.com/merlin-gate/merlin/internal/policy"
)

// These tests assert the WIRING, not the cache. internal/policies/grype owns whether
// reuse is sound; what can only go wrong here is the plumbing — a store handed to the
// wrong option, an observer pointed at a registry nobody scrapes, or a live Valkey
// dial on the hermetic path. Each of those compiles, starts, and looks healthy while
// the cache does nothing, so the assertions below go all the way through to observable
// behaviour rather than counting options.

// countingRunner records how many scans actually ran.
type countingRunner struct {
	mu    sync.Mutex
	calls int
	rep   grype.Report
}

func (c *countingRunner) Scan(context.Context, string) (grype.Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.rep, nil
}

func (c *countingRunner) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// memStore is an in-process stand-in for Valkey. The real store has its own tests;
// here it only has to be a working ReportStore so reuse is observable.
type memStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStore() *memStore { return &memStore{data: map[string][]byte{}} }

func (m *memStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	return v, ok, nil
}

func (m *memStore) Set(_ context.Context, key string, val []byte, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = val
	return nil
}

// pushTwice evaluates the same digest twice through a policy built from the given
// options and reports how many scans that took.
func pushTwice(t *testing.T, opts []grype.Option) int {
	t.Helper()
	r := &countingRunner{rep: grype.Report{
		DBVersion: "schema v6.1.9 built recently",
		DBBuilt:   time.Now().UTC().Add(-1 * time.Hour),
	}}
	p := grype.New(r, "CRITICAL", opts...)
	img := policy.StagedImage{OCIPath: "/oci", Digest: "sha256:wiring"}
	for i := 0; i < 2; i++ {
		if _, err := p.Evaluate(context.Background(), img); err != nil {
			t.Fatalf("evaluate %d: %v", i, err)
		}
	}
	return r.count()
}

func TestScanCacheOptionsMakeASecondPushReuse(t *testing.T) {
	opts := grypeOptions(scanCacheConfig("24h"), policyDeps{ScanCache: newMemStore()})
	if got := pushTwice(t, opts); got != 1 {
		t.Errorf("two pushes of one digest ran %d scans, want 1: the store did not reach the policy", got)
	}
}

func TestWithoutAStoreEveryPushScans(t *testing.T) {
	// The counterpart assertion: reuse must come from the store being wired, not from
	// something in the policy defaults. If this ever returns 1, the cache is on for
	// deployments that never asked for it.
	if got := pushTwice(t, grypeOptions(minimalConfig(), policyDeps{})); got != 2 {
		t.Errorf("with no store configured, two pushes ran %d scans, want 2", got)
	}
}

func TestScanCacheConfiguredWindowReachesThePolicy(t *testing.T) {
	// A one-minute window with an hour-old DB must refuse the cached report. This is
	// the only way to tell max_db_age was passed through at all: a dropped value would
	// leave the policy on its own 24h default, where both pushes reuse and the test
	// above still passes.
	opts := grypeOptions(scanCacheConfig("1m"), policyDeps{ScanCache: newMemStore()})
	if got := pushTwice(t, opts); got != 2 {
		t.Errorf("a 1m window over a 1h-old DB ran %d scans, want 2: max_db_age was not applied", got)
	}
}

func TestScanCacheHitsAndMissesReachTheMetricsRegistry(t *testing.T) {
	// An observer wired to a registry nobody scrapes is indistinguishable from no
	// observer, so scrape the real handler rather than asserting the field is set.
	_, metrics := newMetrics()
	opts := grypeOptions(scanCacheConfig("24h"), policyDeps{
		ScanCache: newMemStore(),
		CacheObs:  metrics,
	})
	if got := pushTwice(t, opts); got != 1 {
		t.Fatalf("expected reuse, got %d scans", got)
	}

	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`merlin_scan_cache_total{result="hit"} 1`,
		`merlin_scan_cache_total{result="miss"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %q; the cache observer is not wired to this registry", want)
		}
	}
}

// --- store construction ---

func scanCacheConfig(window string) config.Config {
	cfg := minimalConfig()
	cfg.Staging.ValkeyAddr = "merlin-valkey:6379"
	cfg.Grype.ScanCache = config.ScanCacheConfig{Enabled: true, MaxDBAge: window}
	return cfg
}

func TestNoStoreIsBuiltWhenTheCacheIsDisabled(t *testing.T) {
	// A disabled cache must not dial anything, even with an address configured — the
	// address is there for staging state regardless.
	cfg := minimalConfig()
	cfg.Staging.ValkeyAddr = "127.0.0.1:1"
	store, closeStore, err := buildScanCache(cfg)
	if err != nil {
		t.Fatalf("a disabled scan cache must not fail the build: %v", err)
	}
	if store != nil {
		t.Errorf("store = %T, want nil when the cache is disabled", store)
	}
	if closeStore != nil {
		closeStore()
	}
}

func TestEnabledScanCacheFailsFastOnAnUnreachableValkey(t *testing.T) {
	// Fail at startup, not on the first push. A pod that came up with a dead cache and
	// no complaint would scan everything while the config says reuse is on, and the
	// hit-rate panel would read 0% with nothing to say why.
	cfg := scanCacheConfig("24h")
	cfg.Staging.ValkeyAddr = "127.0.0.1:1"
	if _, _, err := buildScanCache(cfg); err == nil {
		t.Fatal("expected a connection error for an unreachable valkey")
	}
}

func TestEnabledScanCacheRejectsAnUnparseableWindow(t *testing.T) {
	// config.validate() catches this for a loaded config; this covers the one built in
	// code, where a bad window would otherwise be swallowed and the cache silently
	// left on its default.
	cfg := scanCacheConfig("yesterday")
	cfg.Staging.ValkeyAddr = "127.0.0.1:1"
	_, _, err := buildScanCache(cfg)
	if err == nil {
		t.Fatal("expected an error for an unparseable max_db_age")
	}
	if !strings.Contains(err.Error(), "max_db_age") {
		t.Errorf("error should name the field, got %q", err)
	}
}

func TestHermeticBuildDoesNotDialValkey(t *testing.T) {
	// Build is the offline path. An enabled scan cache pointing at nothing must not
	// stop it, because the store is a live backend and Build has none.
	cfg := scanCacheConfig("24h")
	cfg.Staging.ValkeyAddr = "127.0.0.1:1"
	if _, err := Build(cfg); err != nil {
		t.Fatalf("hermetic Build must ignore the scan cache, got: %v", err)
	}
}
