package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

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
	"github.com/merlin-gate/merlin/internal/scancache"
	"github.com/merlin-gate/merlin/internal/staging"
	"github.com/merlin-gate/merlin/internal/tenant"
)

// closerStack collects the release functions a build acquires and runs them in
// REVERSE order of acquisition.
//
// The order is load-bearing rather than tidy. The auditor drains its queue into the
// ClickHouse writer when it closes, so a writer closed first would silently discard
// every decision still buffered — a scan that ran, blocked or passed an image, and
// left no record. R0 could not assert this: the slice was a local inside a 331-line
// function and cleanup() returned nothing, so order was unobservable from outside the
// package. Naming it makes the order a property with its own test.
type closerStack struct{ fns []func() }

// push registers fn. A nil fn is ignored, so a component that opens nothing (or is
// switched off in config) needs no branch at the call site.
func (s *closerStack) push(fn func()) {
	if fn == nil {
		return
	}
	s.fns = append(s.fns, fn)
}

// closeAll runs every registered function, last acquired first.
func (s *closerStack) closeAll() {
	for i := len(s.fns) - 1; i >= 0; i-- {
		s.fns[i]()
	}
}

// validateProductionConfig checks every field the live backends need BEFORE any
// client is constructed, so the failure a misconfigured deployment gets is a
// startup error naming the field rather than a network timeout.
//
// The order is the order the fields are consumed in, and it is asserted: a caller
// missing several of them should be told about the first one it will hit.
func validateProductionConfig(cfg config.Config) error {
	if cfg.ACR.RegistryTemplate == "" {
		return fmt.Errorf("production config: ACR.RegistryTemplate is required")
	}
	if cfg.ACR.BaseDomain == "" {
		return fmt.Errorf("production config: ACR.BaseDomain is required")
	}
	if len(cfg.Tenants) == 0 {
		return fmt.Errorf("production config: at least one tenant is required")
	}
	if cfg.Auth.RegistryTokenSecret == "" {
		return fmt.Errorf("production config: Auth.RegistryTokenSecret is required")
	}
	if cfg.Server.ExternalURL == "" {
		return fmt.Errorf("production config: Server.ExternalURL is required")
	}
	if cfg.Staging.BlobAccountURL == "" {
		return fmt.Errorf("production config: Staging.BlobAccountURL is required")
	}
	if cfg.Staging.ValkeyAddr == "" {
		return fmt.Errorf("production config: Staging.ValkeyAddr is required")
	}
	if cfg.Audit.ClickHouseDSN == "" {
		return fmt.Errorf("production config: Audit.ClickHouseDSN is required")
	}
	return nil
}

// authComponents is the whole auth surface: who may push, which ACR their pushes
// reach, and the tokens Merlin mints for itself.
type authComponents struct {
	// Tenants is keyed by DNS PREFIX. The promotion worker resolves pushers from
	// this same map rather than by repo name: two tenants may host the same repo
	// against different registries, so keying on repo could publish to the wrong ACR.
	Tenants map[string]*tenant.Tenant

	// Resolver binds a request host to its tenant by DNS prefix. This host->tenant
	// mapping is the security boundary — it decides which ACR a push may reach — so
	// it is always a real static resolver built from config.
	Resolver tenant.Resolver

	// Issuer mints and verifies Merlin's own registry tokens (the ones the docker
	// client replays on /v2/ after the challenge).
	Issuer *auth.RegistryTokenIssuer

	// ClientCreds validates Entra client-credentials logins at /token. Shared across
	// tenants, using the first tenant's Entra tenant and audience; per-tenant client
	// credentials are out of scope (see the multi-ACR plan).
	ClientCreds auth.ClientCredentialsValidator
}

// buildAuth constructs the per-tenant auth surface. ctx bounds the JWKS refresh
// goroutine each tenant's keyfunc starts, so cancelling it stops them all.
//
// It opens no closable resource, which is why it returns no closer: the only thing
// it starts is tied to ctx.
//
// Requires a validated config — it indexes cfg.Tenants[0] for the shared
// client-credentials validator, which validateProductionConfig has already
// guaranteed exists.
func buildAuth(ctx context.Context, cfg config.Config) (authComponents, error) {
	tenants := make(map[string]*tenant.Tenant, len(cfg.Tenants))
	for _, tc := range cfg.Tenants {
		registry := tc.Registry(cfg.ACR.RegistryTemplate)
		kf, err := auth.NewEntraKeyfunc(ctx, tc.Auth.JWKSURL)
		if err != nil {
			return authComponents{}, fmt.Errorf("tenant %s: JWKS keyfunc: %w", tc.Prefix, err)
		}
		tAuthn := auth.NewJWTAuthenticator(tc.Auth.Issuer, tc.Auth.Audience, kf)
		tPusher, err := acr.NewACRPusherWithClientID(registry, tc.ACRClientID)
		if err != nil {
			return authComponents{}, fmt.Errorf("tenant %s: ACR pusher: %w", tc.Prefix, err)
		}
		tenants[tc.Prefix] = &tenant.Tenant{
			Prefix:   tc.Prefix,
			Registry: registry,
			Pusher:   tPusher,
			Authn:    tAuthn,
		}
	}

	ttl, err := time.ParseDuration(cfg.Auth.RegistryTokenTTL)
	if err != nil {
		return authComponents{}, fmt.Errorf("parse registry_token_ttl: %w", err)
	}

	return authComponents{
		Tenants:     tenants,
		Resolver:    tenant.NewStaticResolver(cfg.ACR.BaseDomain, tenants),
		Issuer:      auth.NewRegistryTokenIssuer([]byte(cfg.Auth.RegistryTokenSecret), cfg.Auth.Service, ttl),
		ClientCreds: auth.NewEntraClientCredentials(cfg.Tenants[0].Auth.TenantID, cfg.Tenants[0].Auth.Audience+"/.default"),
	}, nil
}

// buildStaging opens the blob store and the Valkey session store and joins them
// into the staging store the upload path writes through.
//
// No closer: neither backing client exposes one today. Naming that here is the
// point — the alternative is a reader assuming the omission is an oversight.
func buildStaging(cfg config.Config) (*staging.Store, error) {
	blobStore, err := staging.NewAzureBlobStoreWithCredential(cfg.Staging.BlobAccountURL, cfg.Staging.BlobContainer)
	if err != nil {
		return nil, fmt.Errorf("create blob store: %w", err)
	}
	sessionTTL, err := time.ParseDuration(cfg.Staging.SessionTTL)
	if err != nil {
		return nil, fmt.Errorf("parse staging.session_ttl: %w", err)
	}
	sessionStore, err := staging.NewValkeySessionStoreWithTTL(cfg.Staging.ValkeyAddr, sessionTTL)
	if err != nil {
		return nil, fmt.Errorf("create session store: %w", err)
	}
	return staging.New(blobStore, sessionStore, generatePushID), nil
}

// buildPromotion dials the durable promotion queue.
//
// It reaches the same Valkey the session store already reached, so an unreachable
// Valkey surfaces from buildStaging as "create session store" and never from here —
// which is why the error-precedence table in wiring_live_test.go still holds after
// this dial moved ahead of the audit writer.
func buildPromotion(cfg config.Config) (promote.Queue, error) {
	q, err := promote.NewValkeyQueueAtAddr(cfg.Staging.ValkeyAddr, promote.DefaultKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("create promote queue: %w", err)
	}
	return q, nil
}

// auditComponents is the audit trail: the sink gate decisions are recorded to, and
// the reader that serves them back to /reports and the dashboard.
type auditComponents struct {
	Auditor *audit.Auditor
	Reports *audit.Reader
}

// buildAudit opens the ClickHouse writer, wraps it in the buffering auditor, and
// opens the reader. The returned closer releases all three in reverse order; on a
// partial failure it releases what was already open before returning, so the caller
// never has to unwind a half-built audit trail.
func buildAudit(cfg config.Config) (auditComponents, func(), error) {
	var stack closerStack

	// The WRITER is constructed first because it bootstraps the schema (CREATE
	// DATABASE + tables); the reader below has nothing to read until it has run.
	writer, err := audit.NewClickHouseWriter(cfg.Audit.ClickHouseDSN, cfg.Audit.RetentionDays)
	if err != nil {
		return auditComponents{}, nil, fmt.Errorf("create audit writer: %w", err)
	}
	if wc, ok := writer.(interface{ Close() error }); ok {
		stack.push(func() { wc.Close() })
	}

	auditor := audit.NewAuditor(writer, cfg.Audit.QueueSize, func(d audit.Decision, err error) {
		// A dropped decision means a scan ran but its audit record was lost — the
		// report endpoint will then have nothing to serve for that image. Log which
		// image was affected so this is diagnosable instead of silently invisible.
		log.Printf("audit drop: decision NOT recorded for %s/%s (push_id=%s passed=%t): %v",
			d.Repo, d.Tag, d.PushID, d.Passed, err)
	})
	// Pushed AFTER the writer, so closeAll drains the auditor into a writer that is
	// still open. Reversing these two loses whatever the queue was holding.
	stack.push(func() { auditor.Close() })

	reader, err := audit.NewClickHouseReader(cfg.Audit.ClickHouseDSN)
	if err != nil {
		stack.closeAll()
		return auditComponents{}, nil, fmt.Errorf("create audit reader: %w", err)
	}
	stack.push(func() { reader.Close() })

	return auditComponents{Auditor: auditor, Reports: reader}, stack.closeAll, nil
}

// newMetrics builds the Prometheus registry and the metric set over it.
//
// Called BEFORE the policies on both build paths: the grype policy is the only
// component that sees the scanner DB's build date, so it is what carries the age
// observer, and it cannot be constructed until the observer exists.
func newMetrics() (*prometheus.Registry, *observability.Metrics) {
	reg := prometheus.NewRegistry()
	return reg, observability.NewMetrics(reg)
}

// buildPolicyEngine assembles the three policies and the engine that runs them.
//
// Both build paths call this, and that is the point: the hermetic and production
// wirings used to contain the same five lines twice, so a policy added to one and
// not the other diverged silently. There is now one place to add a policy.
func buildPolicyEngine(cfg config.Config, deps policyDeps) (*policy.Engine, error) {
	runner, err := grypeRunner(cfg)
	if err != nil {
		return nil, err
	}
	grypePolicy := grype.New(runner, cfg.Grype.SeverityThreshold, grypeOptions(cfg, deps)...)
	basePolicy := baseimage.New(cfg.BaseImage.AllowedIDs)
	def, per := imageAgeRules(cfg)
	// imageage stays OUTSIDE the cached report on purpose. Its verdict depends on the
	// wall clock, so a cached decision would keep passing an image that crossed
	// threshold_days overnight. Only the scan is reused; every policy still runs.
	return policy.NewEngine(grypePolicy, basePolicy, imageage.New(def, per)), nil
}

// buildScanCache builds the shared store that lets an identical manifest digest skip
// a re-scan. Returns (nil, nil, nil) when the cache is off, which is the default.
//
// A misconfigured-but-enabled cache is fatal rather than degraded. The failure it
// prevents is quiet: a pod that came up with a dead store would scan everything while
// the config says reuse is on, and the hit-rate panel would sit at 0% with nothing to
// say why. Once running, every cache fault IS degraded — see internal/scancache.
func buildScanCache(cfg config.Config) (grype.ReportStore, func(), error) {
	if !cfg.Grype.ScanCache.Enabled {
		return nil, nil, nil
	}
	// Parsed here as well as in config.validate() because a Config built in code never
	// went through validate, and a bad window must not reach the policy as a zero.
	if _, err := cfg.Grype.ScanCache.MaxDBAgeDuration(); err != nil {
		return nil, nil, fmt.Errorf("scan cache: %w", err)
	}
	if cfg.Staging.ValkeyAddr == "" {
		return nil, nil, fmt.Errorf("scan cache: staging.valkey_addr is empty; the store is shared across replicas")
	}
	store, err := scancache.NewValkeyStoreAtAddr(cfg.Staging.ValkeyAddr, scancache.DefaultOpTimeout)
	if err != nil {
		return nil, nil, err
	}
	return store, func() { _ = store.Close() }, nil
}

// buildOutcome builds the Docker outcome adapter — what turns a gate verdict into an
// HTTP response, an audit record and metrics.
//
// recorder may be nil (hermetic: no audit trail). idGen may be nil, in which case
// the docker package's own generator is used; the two differ, deliberately for now —
// see the note on Build.
//
// metrics must ALSO satisfy dockeringress.ACRPushObserver, not just MetricsObserver.
// The handler reaches the ACR push counter by TYPE ASSERTION on this field
// (Handler.acrPushObserver), so a sink implementing only MetricsObserver compiles,
// wires, and silently stops counting real ACR pushes. That is the assertion R0
// deferred as unobservable, and it is checkable now that the outcome is a returned
// value rather than a local in a 331-line function.
func buildOutcome(recorder dockeringress.DecisionRecorder, metrics dockeringress.MetricsObserver, idGen func() string) *dockeringress.Outcome {
	return &dockeringress.Outcome{
		ReportBaseURL: "/reports",
		Recorder:      recorder,
		IDGen:         idGen,
		Metrics:       metrics,
	}
}

// ingressDeps is what the docker ingress handler is wired from: one field per component
// built before it. It exists so the handler's config — seventeen fields, most of them
// carrying a reason — reads as one unit instead of inflating the build sequence.
type ingressDeps struct {
	Auth        authComponents
	Store       *staging.Store
	Reports     dockeringress.ReportSource
	Router      *router.Router
	Outcome     *dockeringress.Outcome
	Requests    dockeringress.RequestObserver
	Queue       promote.Queue
	GateTimeout time.Duration
}

// buildIngress builds the docker ingress handler. New validates the couplings between
// these fields, so an inert knob is a startup failure here rather than a value that
// reads as configured in the ConfigMap and does nothing.
func buildIngress(cfg config.Config, d ingressDeps) (*dockeringress.Handler, error) {
	return dockeringress.New(dockeringress.HandlerConfig{
		Resolver: d.Auth.Resolver,
		Router:   d.Router,
		Outcome:  d.Outcome,
		Store:    d.Store,
		Reports:  d.Reports,
		// Count requests answered before a decision exists (401, 404, shed 503).
		Requests: d.Requests,
		Pool:     router.NewPool(d.Router, cfg.Staging.ScanPoolSize),
		// Budgets the slot wait and the scan separately, one gateTimeout each.
		GateTimeout:    d.GateTimeout,
		MaxUploadBytes: cfg.Server.MaxUploadBytes,
		// Bound concurrent upload memory. Separate from the scan pool above: that one
		// is sized for Grype CPU, while this caps how many pushes may buffer blob bytes
		// at once (staging re-reads the accumulated upload on every chunk, so the
		// resident cost is a multiple of max_upload_bytes per in-flight upload).
		UploadConcurrency: cfg.Server.UploadConcurrency,
		ScratchBaseDir:    cfg.Staging.ScratchDir,
		// Registry auth: verify Merlin's own token on /v2/, and point the challenge at
		// the /token endpoint the TokenHandler below serves.
		RegistryIssuer: d.Auth.Issuer,
		TokenRealm:     cfg.Server.ExternalURL + "/token",
		Service:        cfg.Auth.Service,
		TokenHandler: &dockeringress.TokenHandler{
			Resolver:    d.Auth.Resolver,
			ClientCreds: d.Auth.ClientCreds,
			Issuer:      d.Auth.Issuer,
		},
		// Deferred ACR publication. Both push clients hardcode a 30s
		// ResponseHeaderTimeout that no flag can raise, so the manifest PUT cannot be
		// held across the ACR push: the scan stays synchronous (the verdict must remain
		// in the push exit code) and only publication moves to the durable queue.
		Promoter: promote.QueuePromoter{Queue: d.Queue},
		// Bound the backlog. The 201 goes out while the job is still queued, so nothing
		// but the worker's drain rate limits how much scratch the pending layouts hold —
		// and scratch is a per-pod emptyDir.
		MaxPendingPromotions: dockeringress.DefaultMaxPendingPromotions,
	})
}

// buildDashboard builds the dashboard server and returns the DecisionRecorder gate
// decisions must go through from here on.
//
// The recorder is the RETURN VALUE rather than a field assigned afterwards: when the
// dashboard is live, decisions are teed into its feed, and everything that records —
// the request path and the promotion worker both — has to pick up the tee rather than
// the bare auditor. Returning it means the outcome is complete at construction
// instead of being patched once the dashboard is known.
//
// The server is nil when dashboard_addr is "off" or empty, and also when the renderer
// fails to build: the dashboard must never keep the gate from serving, so a renderer
// failure is logged and the process continues. In that case the returned recorder is
// still the tee — harmless, since a broadcaster with no server has no subscribers.
func buildDashboard(cfg config.Config, reg prometheus.Gatherer, reports audit.DashboardReader, auditor *audit.Auditor) (*http.Server, dockeringress.DecisionRecorder) {
	if strings.EqualFold(cfg.Server.DashboardAddr, "off") || cfg.Server.DashboardAddr == "" {
		return nil, auditor
	}

	broadcaster := dashboard.NewBroadcaster(64)
	// Tee gate decisions into the live feed without changing the audit path.
	recorder := dashboard.NewTeeRecorder(auditor, broadcaster)

	rnd, err := dashboard.NewRenderer()
	if err != nil {
		// Log and continue: the dashboard must never fail the process.
		log.Printf("dashboard disabled: renderer: %v", err)
		return nil, recorder
	}
	svc := dashboard.NewService(reports, reg, nil)
	return &http.Server{
		Addr:    cfg.Server.DashboardAddr,
		Handler: dashboard.NewServer(svc, rnd, broadcaster, nil),
	}, recorder
}

// sweepScratchAtStartup reclaims scratch dirs stranded by a previous crash.
//
// Assembly cleanup is deferred, and a SIGKILL (OOMKill) runs no defers, so those dirs
// are unreferenced and would otherwise accumulate until the volume fills — 15.7G had
// built up this way. Startup is the safe moment: no assembly is in flight yet.
// Non-fatal — a sweep failure must not stop the gate from serving.
func sweepScratchAtStartup(cfg config.Config) {
	if cfg.Staging.ScratchDir == "" {
		return
	}
	if n, err := staging.SweepScratch(cfg.Staging.ScratchDir, staging.DefaultScratchMaxAge); err != nil {
		log.Printf("scratch sweep failed for %s: %v", cfg.Staging.ScratchDir, err)
	} else if n > 0 {
		log.Printf("scratch sweep: reclaimed %d abandoned scratch dir(s) under %s", n, cfg.Staging.ScratchDir)
	}
}

// startPromoteWorker starts the goroutine that drains the promotion queue into ACR.
//
// recorder must be whatever is ACTUALLY recording by now — the tee when the dashboard
// is live, the bare auditor otherwise. Reusing it means an abandoned promotion appears
// on exactly the same surfaces as a synchronous failure rather than skipping the live
// feed.
func startPromoteWorker(
	ctx context.Context,
	cfg config.Config,
	queue promote.Queue,
	store *staging.Store,
	tenants map[string]*tenant.Tenant,
	recorder dockeringress.DecisionRecorder,
	metrics *observability.Metrics,
) {
	worker := &promote.Worker{
		Queue: queue,
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
		Recorder: promote.AuditFinalizer{Recorder: recorder},
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
	go worker.Run(ctx)
}

// startSamplers samples the two levels deferred promotion made load-bearing, and
// keeps sweeping scratch.
//
// Both are levels held between events, so nothing updates them on the request path.
// The startup-only sweep is no longer sufficient either: a cross-pod promotion
// rebuilds the layout locally and the ORIGIN pod's merlin-assemble-* dir becomes
// unreachable by any running code (its owner is on the other replica), so scratch now
// leaks during NORMAL operation rather than only after a crash.
func startSamplers(ctx context.Context, cfg config.Config, queue promote.Queue, metrics *observability.Metrics) {
	go func() {
		t := time.NewTicker(promoteSampleInterval)
		defer t.Stop()
		sweepAt := time.Now().Add(scratchSweepInterval)
		for {
			if depth, err := queue.Depth(ctx); err == nil {
				metrics.SetPendingPromotions(depth)
			}
			if bytes, err := staging.ScratchBytes(cfg.Staging.ScratchDir); err == nil {
				metrics.SetScratchBytes(bytes)
			}
			if !time.Now().Before(sweepAt) {
				sweepAt = time.Now().Add(scratchSweepInterval)
				if n, err := staging.SweepScratch(cfg.Staging.ScratchDir, staging.DefaultScratchMaxAge); err != nil {
					log.Printf("scratch sweep failed for %s: %v", cfg.Staging.ScratchDir, err)
				} else if n > 0 {
					log.Printf("scratch sweep: reclaimed %d abandoned scratch dir(s) under %s", n, cfg.Staging.ScratchDir)
				}
			}
			select {
			case <-t.C:
			case <-ctx.Done():
				return
			}
		}
	}()
}

// buildServers binds the handlers to their addresses.
//
// One place does the binding, on both paths. That is the whole reason it exists: the
// build used to return three bare *http.Server values positionally, so transposing
// the gate and the dashboard compiled cleanly and served the unauthenticated
// dashboard on the registry port.
func buildServers(cfg config.Config, gate http.Handler, metrics *observability.Metrics, dash *http.Server, closeAll func()) Servers {
	return Servers{
		Gate:      &http.Server{Addr: cfg.Server.Addr, Handler: gate},
		Metrics:   &http.Server{Addr: cfg.Server.MetricsAddr, Handler: metrics.Handler()},
		Dashboard: dash,
		Close:     closeAll,
	}
}
