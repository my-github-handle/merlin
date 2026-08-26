// Package app wires Merlin's components into runnable HTTP servers.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/config"
	dockeringress "github.com/merlin-gate/merlin/internal/ingress/docker"
	"github.com/merlin-gate/merlin/internal/policies/grype"
	"github.com/merlin-gate/merlin/internal/policies/imageage"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/tenant"
)

const (
	// promoteSampleInterval is how often the pending-promotion depth and the scratch
	// footprint are sampled into their gauges. Both are levels held between events, so
	// nothing updates them on the request path; 15s is below a typical scrape interval,
	// which keeps a backlog that stops draining visible in the scrape that matters.
	promoteSampleInterval = 15 * time.Second

	// scratchSweepInterval is how often abandoned scratch dirs are reclaimed while the
	// process runs. The startup-only sweep was sufficient when a leak required a crash;
	// cross-pod promotion strands the origin pod's layout during normal operation, so
	// the sweep has to keep running. The cadence is coarse because SweepScratch only
	// removes dirs older than DefaultScratchMaxAge (24h) — sweeping faster reclaims
	// nothing extra, it just walks the volume more often.
	scratchSweepInterval = time.Hour
)

// Servers is what a build hands back: the listeners to serve, and the single
// function that releases everything they hold.
//
// It replaces a five-value positional return. That return was
// `(*http.Server, *http.Server, *http.Server, func(), error)` — three
// interchangeable pointer types in a row, so transposing the gate and the
// dashboard compiled cleanly and bound the registry protocol to the dashboard's
// port. The R0 wiring tests catch that mutation today; this makes it
// unexpressible instead.
type Servers struct {
	// Gate serves the Docker registry V2 protocol. This is the one whose port
	// clients push to.
	Gate *http.Server

	// Metrics serves the Prometheus endpoint for the registry the gate's
	// components were built over.
	Metrics *http.Server

	// Dashboard is nil when dashboard_addr is "off" or empty, and also when the
	// renderer failed to build — the dashboard must never keep the gate from
	// serving, so its absence is a normal outcome rather than an error.
	Dashboard *http.Server

	// Close releases every backend the build opened, in reverse order of
	// acquisition, and stops the goroutines it started. Non-nil on every
	// successful build, including the hermetic one, so callers never branch on
	// it. Call it AFTER draining the servers: an in-flight push is still using
	// the session store and the blob client.
	Close func()
}

// grypeRunner builds the grype Runner with the configured per-scan memory bound
// applied. The limit string is validated at config load, so an error here means
// the config was constructed in-process rather than loaded from disk.
func grypeRunner(cfg config.Config) (grype.Runner, error) {
	limit, err := cfg.Grype.MemoryLimitBytes()
	if err != nil {
		return nil, err
	}
	return grype.NewExecRunner("grype", grype.WithMemoryLimit(limit)), nil
}

// Build wires config into the V2 server and the metrics server. The returned
// Servers has no Dashboard: the hermetic path wires the request surface only.
//
// It goes through the SAME helpers as BuildWithBackends, with the live backends left
// out. That is what makes the divergence between the two paths readable: everything
// Build omits is a field it does not set on a shared config, not a block of wiring
// that happens to be missing. The differences, in full:
//
//   - Auth is a stub keyfunc that rejects every real token, and there is one fake
//     tenant whose pusher uses the anonymous keychain and never reaches ACR.
//   - No Store and no Reports on the handler: that absence IS the hermetic contract.
//   - No Pool, so scans run unpooled; no promoter, so publication is synchronous.
//   - No scan cache, so every push scans even where grype.scan_cache is enabled: the
//     store is a live Valkey, and dialling one is exactly what this path avoids.
//   - No audit recorder, and no IDGen — which means the docker package's own
//     generator is used. It differs from this package's: on a crypto/rand failure
//     docker's falls back to a timestamp while ours panics. Left as-is here because
//     this commit preserves behaviour; worth reconciling separately.
func Build(cfg config.Config) (Servers, error) {
	_, metrics := newMetrics()
	// No ScanCache: it is a live Valkey dependency, and this path has no backends. An
	// enabled scan_cache in the config is therefore ignored here, not dialled.
	engine, err := buildPolicyEngine(cfg, policyDeps{DBAge: metrics, CacheObs: metrics})
	if err != nil {
		return Servers{}, err
	}

	// Auth — stub keyfunc for hermetic unit testing. Production wiring is buildAuth.
	keyfunc := func(*jwt.Token) (interface{}, error) { return nil, http.ErrAbortHandler }
	authn := auth.NewJWTAuthenticator("https://issuer", "api://merlin", keyfunc)

	// Single fake tenant so the request path is fully wired for unit tests. The
	// resolver is a real static resolver (one entry) so host->tenant binding is
	// exercised, but the pusher uses the anonymous keychain and never reaches ACR.
	const stubPrefix = "test"
	registry := "testacr.azurecr.io"
	if cfg.ACR.RegistryTemplate != "" {
		registry = strings.ReplaceAll(cfg.ACR.RegistryTemplate, "{prefix}", stubPrefix)
	}
	baseDomain := cfg.ACR.BaseDomain
	if baseDomain == "" {
		baseDomain = "test.local"
	}
	resolver := tenant.NewStaticResolver(baseDomain, map[string]*tenant.Tenant{
		stubPrefix: {
			Prefix:   stubPrefix,
			Registry: registry,
			Pusher:   acr.NewACRPusher(registry),
			Authn:    authn,
		},
	})

	// No recorder and no IDGen; metrics still observe push decisions, ACR pushes and
	// scan latency, because those are the assertions the hermetic tests can make.
	handler, err := dockeringress.New(dockeringress.HandlerConfig{
		Resolver: resolver,
		Router:   router.New(engine),
		Outcome:  buildOutcome(nil, metrics, nil),
		Requests: metrics, // count requests answered before a decision exists
	})
	if err != nil {
		return Servers{}, err
	}

	// Close is a no-op rather than nil: Build opens nothing, but a caller that has
	// to check which build produced its Servers before releasing them has gained
	// nothing over the positional return.
	return buildServers(cfg, handler, metrics, nil, func() {}), nil
}

// BuildWithBackends wires config into production servers with REAL backends (JWKS,
// Azure Blob, Valkey, ClickHouse, ACR). Required production config is validated
// BEFORE any live client is constructed, so a misconfigured deployment fails with a
// startup error naming the field rather than a network timeout.
//
// On success every field of the returned Servers is populated except Dashboard, which
// is nil when the dashboard is off. On any error the zero Servers is returned —
// nothing to serve and nothing to close, because fail() has already released whatever
// had been opened, in reverse order.
//
// The body is the SEQUENCE and nothing else. Each step is a helper in components.go
// that owns its own resources and its own closer, which is what makes the closer
// ordering assertable (see closerStack) and the hermetic path above a subset of this
// one rather than a parallel implementation.
func BuildWithBackends(ctx context.Context, cfg config.Config) (Servers, error) {
	if err := validateProductionConfig(cfg); err != nil {
		return Servers{}, err
	}
	gateTimeout, err := time.ParseDuration(cfg.Server.GateTimeout)
	if err != nil {
		return Servers{}, fmt.Errorf("parse gate timeout %q: %w", cfg.Server.GateTimeout, err)
	}

	// --- LIVE BACKENDS (network calls below) ---

	// bctx bounds every goroutine started below: the per-tenant JWKS refreshers, the
	// promotion worker, the samplers and the alerter.
	bctx, cancel := context.WithCancel(ctx)
	var closers closerStack
	fail := func(e error) (Servers, error) {
		cancel()
		closers.closeAll()
		return Servers{}, e
	}

	authc, err := buildAuth(bctx, cfg)
	if err != nil {
		return fail(err)
	}
	store, err := buildStaging(cfg)
	if err != nil {
		return fail(err)
	}
	promQueue, err := buildPromotion(cfg)
	if err != nil {
		return fail(err)
	}
	auditc, closeAudit, err := buildAudit(cfg)
	if err != nil {
		return fail(err)
	}
	closers.push(closeAudit)

	reg, metrics := newMetrics()
	scanCache, closeScanCache, err := buildScanCache(cfg)
	if err != nil {
		return fail(err)
	}
	closers.push(closeScanCache)
	engine, err := buildPolicyEngine(cfg, policyDeps{
		DBAge:     metrics,
		ScanCache: scanCache,
		CacheObs:  metrics,
	})
	if err != nil {
		return fail(err)
	}
	rt := router.New(engine)

	// The dashboard is built BEFORE the outcome because it decides what records gate
	// decisions: with the dashboard live they are teed into its feed. Building it first
	// means the outcome — and therefore the handler and the promotion worker — is
	// complete at construction instead of patched afterwards.
	dashSrv, recorder := buildDashboard(cfg, reg, auditc.Reports, auditc.Auditor)
	outcome := buildOutcome(recorder, metrics, generatePushID)

	sweepScratchAtStartup(cfg)

	// The handler is built ONCE, from a config New validates. Every field used to be a
	// setter call on a handler that was already constructible without it, so a knob
	// whose precondition was unmet silently did nothing.
	handler, err := buildIngress(cfg, ingressDeps{
		Auth:        authc,
		Store:       store,
		Reports:     auditc.Reports,
		Router:      rt,
		Outcome:     outcome,
		Requests:    metrics,
		Queue:       promQueue,
		GateTimeout: gateTimeout,
	})
	if err != nil {
		return fail(err)
	}

	startPromoteWorker(bctx, cfg, promQueue, store, authc.Tenants, outcome.Recorder, metrics)
	startSamplers(bctx, cfg, promQueue, metrics)

	// The alerter polls the audit table and posts findings to Slack. Started last
	// because it only reads, so nothing above depends on it — and fatal if it is
	// configured but cannot connect, since a deployment that believes it is watched and
	// is not is worse than one that knows it isn't.
	alertCloser, err := startAlerter(bctx, cfg)
	if err != nil {
		return fail(fmt.Errorf("start alerter: %w", err))
	}
	closers.push(alertCloser)

	return buildServers(cfg, handler, metrics, dashSrv, func() {
		// Cancel the goroutines first, then release every resource in reverse order of
		// acquisition: a sampler still reading the queue must stop before the queue does.
		cancel()
		closers.closeAll()
	}), nil
}

// generatePushID creates a random 16-byte hex ID for tracking push sessions.
func generatePushID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// policyDeps are the sinks and stores the policies attach to. Every field is
// optional, and each nil is a documented degradation rather than a failure — the
// hermetic path supplies none of them.
type policyDeps struct {
	// DBAge receives the scanner DB's age after every scan. Nil leaves the gauge unset.
	DBAge grype.DBAgeObserver
	// ScanCache holds reusable scan reports. Nil means every push scans, which is what
	// every deployment did before the cache existed and still does by default.
	ScanCache grype.ReportStore
	// CacheObs counts cache hits and misses. Nil leaves the hit rate unreported;
	// reuse still happens.
	CacheObs grype.ScanCacheObserver
}

// grypeOptions derives the Grype policy options from config and deps. A nil Enforce
// means the config was built in code rather than parsed (applyDefaults sets it), so
// it is treated as enforcing — the fail-safe direction.
//
// Non-enforcement is logged loudly at every startup on purpose: it publishes
// images with Critical CVEs, so it needs to be visible in the pod logs of every
// restart rather than discoverable only by reading values.yaml.
func grypeOptions(cfg config.Config, deps policyDeps) []grype.Option {
	// Reported on every evaluation: the DB is downloaded at runtime and auto-updates,
	// so grype's own output is the only place Merlin can learn how old it is.
	opts := []grype.Option{grype.WithDBAgeObserver(deps.DBAge)}
	if deps.ScanCache != nil {
		// buildScanCache parsed this before deciding to hand over a store at all, so an
		// error here means the config changed underneath us. Skip the cache rather than
		// pass a zero window, which the policy would apply as "every entry is stale":
		// reuse silently off is recoverable, a wrong freshness bound is not.
		if maxDBAge, err := cfg.Grype.ScanCache.MaxDBAgeDuration(); err != nil {
			log.Printf("WARNING: scan cache disabled: %v", err)
		} else {
			opts = append(opts,
				grype.WithReportCache(deps.ScanCache, maxDBAge),
				grype.WithScanCacheObserver(deps.CacheObs),
			)
		}
	}
	if cfg.Grype.Enforce == nil || *cfg.Grype.Enforce {
		return opts
	}
	log.Printf("WARNING: grype.enforce=false — vulnerability findings at/above %s are recorded but DO NOT block publication. Images with Critical CVEs will reach ACR.", cfg.Grype.SeverityThreshold)
	return append(opts, grype.Observe())
}

// imageAgeRules derives the default age rule and the per-tenant overrides from
// config. A nil per-tenant ImageAge inherits the deployment default.
func imageAgeRules(cfg config.Config) (imageage.Rule, map[string]imageage.Rule) {
	def := imageage.Rule{
		Enabled:       cfg.ImageAge.Enabled == nil || *cfg.ImageAge.Enabled,
		ThresholdDays: cfg.ImageAge.ThresholdDays,
	}
	per := make(map[string]imageage.Rule, len(cfg.Tenants))
	for _, tc := range cfg.Tenants {
		if tc.ImageAge == nil {
			continue
		}
		r := def // start from the default, override present fields
		if tc.ImageAge.Enabled != nil {
			r.Enabled = *tc.ImageAge.Enabled
		}
		if tc.ImageAge.ThresholdDays != 0 {
			r.ThresholdDays = tc.ImageAge.ThresholdDays
		}
		per[tc.Prefix] = r
	}
	return def, per
}
