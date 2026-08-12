// Package app wires Merlin's components into runnable HTTP servers.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/golang-jwt/jwt/v5"
	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/config"
	"github.com/merlin-gate/merlin/internal/dashboard"
	dockeringress "github.com/merlin-gate/merlin/internal/ingress/docker"
	"github.com/merlin-gate/merlin/internal/observability"
	"github.com/merlin-gate/merlin/internal/policies/baseimage"
	"github.com/merlin-gate/merlin/internal/policies/grype"
	"github.com/merlin-gate/merlin/internal/policies/imageage"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/promote"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
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

// Build wires config into the V2 server and the metrics server.
//
// TODO(production / BuildWithBackends): Build is intentionally HERMETIC — it wires
// the request path for unit testing with NO live backends. Before this proxy is
// production-usable, a BuildWithBackends variant (env-gated) MUST wire:
//   - JWKS keyfunc: replace the stub keyfunc with an Entra ID JWKS-backed validator
//     (RS256) — the current stub rejects all real tokens.
//   - staging.Store: Azure Blob + Valkey (currently nil) — required for blob upload
//     and image assembly; the handler cannot process a real push without it.
//   - audit.Auditor: ClickHouse-backed Auditor for the audit trail and reverse lookups.
//   - reports.ReportSource: back GET /reports/<push_id> (currently nil -> 404).
//   - ACR pusher: Azure Managed Identity credentials (NewACRPusher currently uses an
//     anonymous authenticator placeholder).
//   - handleManifest/handleUpload: full V2 flow wiring + router.ErrSaturated->503
//     (see TODO(phase5) in manifest.go/upload.go) with a deadline-bearing context.
func Build(cfg config.Config) (*http.Server, *http.Server, error) {
	// Policies + engine.
	runner, err := grypeRunner(cfg)
	if err != nil {
		return nil, nil, err
	}
	// Metrics are constructed BEFORE the policies: the grype policy is the only
	// component that sees the scanner DB's build date, so it holds the age observer.
	reg := prometheus.NewRegistry()
	metrics := observability.NewMetrics(reg)

	grypePolicy := grype.New(runner, cfg.Grype.SeverityThreshold, grypeOptions(cfg, metrics)...)
	basePolicy := baseimage.New(cfg.BaseImage.AllowedIDs)
	def, per := imageAgeRules(cfg)
	agePolicy := imageage.New(def, per)
	engine := policy.NewEngine(grypePolicy, basePolicy, agePolicy)

	// Auth — stub keyfunc for hermetic unit testing. See TODO(production / BuildWithBackends)
	// for production wiring requirements.
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
	tenants := map[string]*tenant.Tenant{
		stubPrefix: {
			Prefix:   stubPrefix,
			Registry: registry,
			Pusher:   acr.NewACRPusher(registry),
			Authn:    authn,
		},
	}
	resolver := tenant.NewStaticResolver(baseDomain, tenants)

	// Router + Docker outcome/ingress.
	rt := router.New(engine)
	outcome := &dockeringress.Outcome{
		ReportBaseURL: "/reports",
	}
	handler := dockeringress.NewHandler(resolver, nil, rt, outcome, nil)

	// Metrics (registry built above, with the policies).
	outcome.Metrics = metrics           // observe push decisions, ACR pushes, scan latency
	handler.SetRequestObserver(metrics) // count requests answered before a decision exists

	mainSrv := &http.Server{Addr: cfg.Server.Addr, Handler: handler}
	metricsSrv := &http.Server{Addr: cfg.Server.MetricsAddr, Handler: metrics.Handler()}
	return mainSrv, metricsSrv, nil
}

// BuildWithBackends wires config into production servers with REAL backends (JWKS, Azure Blob,
// Valkey, ClickHouse, ACR). It validates required production config fields BEFORE constructing
// any live client, ensuring unit tests can verify config validation without hitting the network.
//
// Returns main server, metrics server, dashboard server (nil if dashboard_addr empty), cleanup func, and error.
func BuildWithBackends(ctx context.Context, cfg config.Config) (*http.Server, *http.Server, *http.Server, func(), error) {
	// VALIDATE-FIRST: Check required production fields before constructing live clients.
	// This allows unit tests to exercise validation logic without network calls.
	if cfg.ACR.RegistryTemplate == "" {
		return nil, nil, nil, nil, fmt.Errorf("production config: ACR.RegistryTemplate is required")
	}
	if cfg.ACR.BaseDomain == "" {
		return nil, nil, nil, nil, fmt.Errorf("production config: ACR.BaseDomain is required")
	}
	if len(cfg.Tenants) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("production config: at least one tenant is required")
	}
	if cfg.Auth.RegistryTokenSecret == "" {
		return nil, nil, nil, nil, fmt.Errorf("production config: Auth.RegistryTokenSecret is required")
	}
	if cfg.Server.ExternalURL == "" {
		return nil, nil, nil, nil, fmt.Errorf("production config: Server.ExternalURL is required")
	}
	if cfg.Staging.BlobAccountURL == "" {
		return nil, nil, nil, nil, fmt.Errorf("production config: Staging.BlobAccountURL is required")
	}
	if cfg.Staging.ValkeyAddr == "" {
		return nil, nil, nil, nil, fmt.Errorf("production config: Staging.ValkeyAddr is required")
	}
	if cfg.Audit.ClickHouseDSN == "" {
		return nil, nil, nil, nil, fmt.Errorf("production config: Audit.ClickHouseDSN is required")
	}

	// Parse gate timeout
	gateTimeout, err := time.ParseDuration(cfg.Server.GateTimeout)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse gate timeout %q: %w", cfg.Server.GateTimeout, err)
	}

	// --- LIVE BACKENDS (network calls below) ---

	// Create cancellable context for JWKS refresh goroutine
	bctx, cancel := context.WithCancel(ctx)

	// Track opened resources for cleanup on error
	var closers []func()
	fail := func(e error) (*http.Server, *http.Server, *http.Server, func(), error) {
		cancel()
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
		return nil, nil, nil, nil, e
	}

	// Per-tenant resolver: each tenant gets its own ACR host, outbound push
	// identity (workload-identity client ID), and inbound Entra auth surface
	// (JWKS keyfunc + JWT authenticator). The resolver binds a request host to
	// its tenant by DNS prefix; this host->tenant mapping is the security
	// boundary, so it MUST be a real static resolver built from config.
	tenants := make(map[string]*tenant.Tenant, len(cfg.Tenants))
	for _, tc := range cfg.Tenants {
		registry := tc.Registry(cfg.ACR.RegistryTemplate)
		kf, err := auth.NewEntraKeyfunc(bctx, tc.Auth.JWKSURL)
		if err != nil {
			return fail(fmt.Errorf("tenant %s: JWKS keyfunc: %w", tc.Prefix, err))
		}
		tAuthn := auth.NewJWTAuthenticator(tc.Auth.Issuer, tc.Auth.Audience, kf)
		tPusher, err := acr.NewACRPusherWithClientID(registry, tc.ACRClientID)
		if err != nil {
			return fail(fmt.Errorf("tenant %s: ACR pusher: %w", tc.Prefix, err))
		}
		tenants[tc.Prefix] = &tenant.Tenant{
			Prefix:   tc.Prefix,
			Registry: registry,
			Pusher:   tPusher,
			Authn:    tAuthn,
		}
	}
	resolver := tenant.NewStaticResolver(cfg.ACR.BaseDomain, tenants)

	// Registry token issuer + client credentials validator
	ttl, err := time.ParseDuration(cfg.Auth.RegistryTokenTTL)
	if err != nil {
		return fail(fmt.Errorf("parse registry_token_ttl: %w", err))
	}
	issuer := auth.NewRegistryTokenIssuer([]byte(cfg.Auth.RegistryTokenSecret), cfg.Auth.Service, ttl)
	// Client-credentials validator is shared across tenants; uses the first tenant's
	// Entra tenant/audience. Per-tenant client-creds is out of scope (see plan).
	cc := auth.NewEntraClientCredentials(cfg.Tenants[0].Auth.TenantID, cfg.Tenants[0].Auth.Audience+"/.default")

	// Staging: Azure Blob + Valkey session store
	blobStore, err := staging.NewAzureBlobStoreWithCredential(cfg.Staging.BlobAccountURL, cfg.Staging.BlobContainer)
	if err != nil {
		return fail(fmt.Errorf("create blob store: %w", err))
	}
	sessionTTL, err := time.ParseDuration(cfg.Staging.SessionTTL)
	if err != nil {
		return fail(fmt.Errorf("parse staging.session_ttl: %w", err))
	}
	sessionStore, err := staging.NewValkeySessionStoreWithTTL(cfg.Staging.ValkeyAddr, sessionTTL)
	if err != nil {
		return fail(fmt.Errorf("create session store: %w", err))
	}
	store := staging.New(blobStore, sessionStore, generatePushID)

	// Audit: ClickHouse writer + auditor + reader
	// IMPORTANT: Writer must be constructed first — it bootstraps the schema (CREATE DATABASE + tables).
	auditWriter, err := audit.NewClickHouseWriter(cfg.Audit.ClickHouseDSN, cfg.Audit.RetentionDays)
	if err != nil {
		return fail(fmt.Errorf("create audit writer: %w", err))
	}
	// Track writer for cleanup (cast to access Close method)
	writerCloser, ok := auditWriter.(interface{ Close() error })
	if ok {
		closers = append(closers, func() { writerCloser.Close() })
	}

	auditor := audit.NewAuditor(auditWriter, cfg.Audit.QueueSize, func(d audit.Decision, err error) {
		// A dropped decision means a scan ran but its audit record was lost — the
		// report endpoint will then have nothing to serve for that image. Log which
		// image was affected so this is diagnosable instead of silently invisible.
		log.Printf("audit drop: decision NOT recorded for %s/%s (push_id=%s passed=%t): %v",
			d.Repo, d.Tag, d.PushID, d.Passed, err)
	})
	closers = append(closers, func() { auditor.Close() })

	reportsReader, err := audit.NewClickHouseReader(cfg.Audit.ClickHouseDSN)
	if err != nil {
		return fail(fmt.Errorf("create audit reader: %w", err))
	}
	closers = append(closers, func() { reportsReader.Close() })

	// Metrics are constructed BEFORE the policies: the grype policy is the only
	// component that sees the scanner DB's build date, so it holds the age observer.
	reg := prometheus.NewRegistry()
	metrics := observability.NewMetrics(reg)

	// Policies + engine
	runner, err := grypeRunner(cfg)
	if err != nil {
		return fail(err)
	}
	grypePolicy := grype.New(runner, cfg.Grype.SeverityThreshold, grypeOptions(cfg, metrics)...)
	basePolicy := baseimage.New(cfg.BaseImage.AllowedIDs)
	def, per := imageAgeRules(cfg)
	agePolicy := imageage.New(def, per)
	engine := policy.NewEngine(grypePolicy, basePolicy, agePolicy)

	// Router + pool
	rt := router.New(engine)
	pool := router.NewPool(rt, cfg.Staging.ScanPoolSize)

	// Docker ingress handler with real backends. The per-request tenant pusher is
	// supplied to Outcome.Apply by the handler, so Outcome holds no Pusher.
	outcome := &dockeringress.Outcome{
		ReportBaseURL: "/reports",
		Recorder:      auditor,
		IDGen:         generatePushID,
	}
	handler := dockeringress.NewHandler(resolver, store, rt, outcome, reportsReader)
	handler.SetPool(pool)
	handler.SetGateTimeout(gateTimeout)
	handler.SetMaxUploadBytes(cfg.Server.MaxUploadBytes)
	// Bound concurrent upload memory. Separate from the scan pool above: that one is
	// sized for Grype CPU, while this caps how many pushes may buffer blob bytes at
	// once (staging re-reads the accumulated upload on every chunk, so the resident
	// cost is a multiple of max_upload_bytes per in-flight upload).
	handler.SetUploadConcurrency(cfg.Server.UploadConcurrency)
	if cfg.Staging.ScratchDir != "" {
		handler.SetScratchBaseDir(cfg.Staging.ScratchDir)
		// Reclaim scratch dirs stranded by a previous crash. Assembly cleanup is
		// deferred, and a SIGKILL (OOMKill) runs no defers, so those dirs are
		// unreferenced and would otherwise accumulate until the volume fills — 15.7G
		// had built up this way. Startup is the safe moment: no assembly is in flight
		// yet. Non-fatal — a sweep failure must not stop the gate from serving.
		if n, err := staging.SweepScratch(cfg.Staging.ScratchDir, staging.DefaultScratchMaxAge); err != nil {
			log.Printf("scratch sweep failed for %s: %v", cfg.Staging.ScratchDir, err)
		} else if n > 0 {
			log.Printf("scratch sweep: reclaimed %d abandoned scratch dir(s) under %s", n, cfg.Staging.ScratchDir)
		}
	}

	// Wire Docker registry auth: token endpoint + challenge
	th := &dockeringress.TokenHandler{Resolver: resolver, ClientCreds: cc, Issuer: issuer}
	handler.SetRegistryAuth(issuer, cfg.Server.ExternalURL+"/token", cfg.Auth.Service)
	handler.SetTokenHandler(th)

	// Metrics (registry built above, with the policies).
	outcome.Metrics = metrics           // observe push decisions, ACR pushes, scan latency
	handler.SetRequestObserver(metrics) // count requests answered before a decision exists

	mainSrv := &http.Server{Addr: cfg.Server.Addr, Handler: handler}
	metricsSrv := &http.Server{Addr: cfg.Server.MetricsAddr, Handler: metrics.Handler()}

	// Dashboard server: on by default, built unless dashboard_addr is "off".
	var dashSrv *http.Server
	if !strings.EqualFold(cfg.Server.DashboardAddr, "off") && cfg.Server.DashboardAddr != "" {
		broadcaster := dashboard.NewBroadcaster(64)
		// Tee gate decisions into the live feed without changing the audit path.
		outcome.Recorder = dashboard.NewTeeRecorder(auditor, broadcaster)

		rnd, derr := dashboard.NewRenderer()
		if derr != nil {
			// Log and continue: the dashboard must never fail the process.
			log.Printf("dashboard disabled: renderer: %v", derr)
		} else {
			svc := dashboard.NewService(reportsReader, reg, nil)
			dashSrv = &http.Server{
				Addr:    cfg.Server.DashboardAddr,
				Handler: dashboard.NewServer(svc, rnd, broadcaster, nil),
			}
		}
	}

	// Deferred ACR promotion. Both push clients hardcode a 30s ResponseHeaderTimeout
	// that no flag can raise, so the manifest PUT cannot be held across the ACR push.
	// The scan stays synchronous (the verdict must remain in the push exit code);
	// only publication moves to a durable queue.
	//
	// Wired AFTER the dashboard block on purpose: outcome.Recorder is whatever is
	// actually recording by now (the tee recorder when the dashboard is on, the bare
	// auditor otherwise). Reusing it means an abandoned promotion appears on exactly
	// the same surfaces as a synchronous failure, rather than skipping the live feed.
	promQueue, err := promote.NewValkeyQueueAtAddr(cfg.Staging.ValkeyAddr, promote.DefaultKeyPrefix)
	if err != nil {
		return fail(fmt.Errorf("create promote queue: %w", err))
	}
	worker := &promote.Worker{
		Queue: promQueue,
		// Resolve by tenant PREFIX, from the same map that built the resolver. A repo
		// name does not identify a tenant: two tenants may host the same repo against
		// different registries, so keying on repo could publish to the wrong ACR.
		Pushers: func(prefix string) (acr.Pusher, error) {
			t, ok := tenants[prefix]
			if !ok {
				return nil, fmt.Errorf("unknown tenant prefix %q", prefix)
			}
			return t.Pusher, nil
		},
		Recorder: promote.AuditFinalizer{Recorder: outcome.Recorder},
		// Rebuild the OCI layout when this pod is not the one that assembled it. The
		// chart mounts scratch as an emptyDir (per pod) while the queue is one shared
		// Valkey list and replicaCount is 2, so roughly half of all jobs are claimed by
		// the wrong pod. The blobs are still reachable — they live in the shared blob
		// store and their ref-counts are released by Cleanup, which has not run yet —
		// so re-assembling locally is all that is needed.
		Localize: func(ctx context.Context, j promote.Job) (string, string, error) {
			dir, err := os.MkdirTemp(cfg.Staging.ScratchDir, "merlin-promote-*")
			if err != nil {
				return "", "", fmt.Errorf("create promote scratch dir: %w", err)
			}
			img, err := store.Assemble(ctx, staging.ManifestRef{
				Repo: j.Repo, Ref: j.Ref, Manifest: j.Manifest,
				ConfigDigest: j.ConfigDig, LayerDigests: j.Layers,
			}, dir)
			if err != nil {
				// Remove the half-built layout: the retry calls Localize again and would
				// otherwise leave one of these per attempt.
				os.RemoveAll(dir)
				return "", "", fmt.Errorf("re-assemble %s: %w", j.Target, err)
			}
			log.Printf("promote %s: rebuilt OCI layout locally (assembled on another replica)", j.PushID)
			return img.OCIPath, dir, nil
		},
		Cleanup: func(ctx context.Context, j promote.Job) error {
			return store.Cleanup(ctx, staging.ManifestRef{
				Repo: j.Repo, Ref: j.Ref, ConfigDigest: j.ConfigDig, LayerDigests: j.Layers,
			}, j.ScratchDir)
		},
		Metrics: metrics,
	}
	go worker.Run(bctx)
	promoter := promote.QueuePromoter{Queue: promQueue}
	handler.SetPromoter(promoter)
	// Bound the backlog. The 201 now goes out while the job is still queued, so
	// nothing but the worker's drain rate limits how much scratch the pending layouts
	// hold — and scratch is a per-pod emptyDir.
	handler.SetMaxPendingPromotions(dockeringress.DefaultMaxPendingPromotions)

	// Sample the two levels deferred promotion made load-bearing, and keep sweeping.
	//
	// The startup-only sweep above is no longer sufficient: a cross-pod promotion
	// rebuilds the layout locally and the ORIGIN pod's merlin-assemble-* dir becomes
	// unreachable by any running code (its owner is on the other replica), so scratch
	// now leaks during NORMAL operation rather than only after a crash.
	go func() {
		t := time.NewTicker(promoteSampleInterval)
		defer t.Stop()
		sweepAt := time.Now().Add(scratchSweepInterval)
		for {
			if depth, derr := promQueue.Depth(bctx); derr == nil {
				metrics.SetPendingPromotions(depth)
			}
			if bytes, berr := staging.ScratchBytes(cfg.Staging.ScratchDir); berr == nil {
				metrics.SetScratchBytes(bytes)
			}
			if !time.Now().Before(sweepAt) {
				sweepAt = time.Now().Add(scratchSweepInterval)
				if n, serr := staging.SweepScratch(cfg.Staging.ScratchDir, staging.DefaultScratchMaxAge); serr != nil {
					log.Printf("scratch sweep failed for %s: %v", cfg.Staging.ScratchDir, serr)
				} else if n > 0 {
					log.Printf("scratch sweep: reclaimed %d abandoned scratch dir(s) under %s", n, cfg.Staging.ScratchDir)
				}
			}
			select {
			case <-t.C:
			case <-bctx.Done():
				return
			}
		}
	}()

	// Alerter: polls the audit table and posts findings to Slack. Started last because
	// it only reads, so nothing above depends on it — and fatal if it is configured but
	// cannot connect, since a deployment that believes it is watched and is not is
	// worse than one that knows it isn't.
	alertCloser, err := startAlerter(bctx, cfg)
	if err != nil {
		return fail(fmt.Errorf("start alerter: %w", err))
	}
	if alertCloser != nil {
		closers = append(closers, alertCloser)
	}

	// Build cleanup function: cancel JWKS context + close all resources (reverse order)
	cleanup := func() {
		cancel() // Stop JWKS background refresh
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	return mainSrv, metricsSrv, dashSrv, cleanup, nil
}

// generatePushID creates a random 16-byte hex ID for tracking push sessions.
func generatePushID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// grypeOptions derives the Grype policy options from config. A nil Enforce means
// the config was built in code rather than parsed (applyDefaults sets it), so it
// is treated as enforcing — the fail-safe direction.
//
// Non-enforcement is logged loudly at every startup on purpose: it publishes
// images with Critical CVEs, so it needs to be visible in the pod logs of every
// restart rather than discoverable only by reading values.yaml.
// grypeOptions derives the grype policy options from config, and wires the
// scanner-DB-age observer. dbAge may be nil (no metrics).
func grypeOptions(cfg config.Config, dbAge grype.DBAgeObserver) []grype.Option {
	// Reported on every scan: the DB is refreshed out-of-band by rebuilding the
	// image, so a scan is the only moment Merlin can learn how old it is.
	opts := []grype.Option{grype.WithDBAgeObserver(dbAge)}
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
