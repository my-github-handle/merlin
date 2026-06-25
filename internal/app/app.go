// Package app wires Merlin's components into runnable HTTP servers.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/golang-jwt/jwt/v5"
	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/config"
	dockeringress "github.com/merlin-gate/merlin/internal/ingress/docker"
	"github.com/merlin-gate/merlin/internal/observability"
	"github.com/merlin-gate/merlin/internal/policies/baseimage"
	"github.com/merlin-gate/merlin/internal/policies/trivy"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
)

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
	trivyPolicy := trivy.New(trivy.NewExecRunner("trivy"), cfg.Trivy.SeverityThreshold)
	basePolicy := baseimage.New(cfg.BaseImage.AllowedIDs)
	engine := policy.NewEngine(trivyPolicy, basePolicy)

	// Auth — stub keyfunc for hermetic unit testing. See TODO(production / BuildWithBackends)
	// for production wiring requirements.
	keyfunc := func(*jwt.Token) (interface{}, error) { return nil, http.ErrAbortHandler }
	authn := auth.NewJWTAuthenticator(cfg.Auth.Issuer, cfg.Auth.Audience, keyfunc)

	// Router + Docker outcome/ingress.
	rt := router.New(engine)
	outcome := &dockeringress.Outcome{
		Pusher:        acr.NewACRPusher(cfg.ACR.Registry),
		ReportBaseURL: "/reports",
	}
	handler := dockeringress.NewHandler(authn, nil, rt, outcome, cfg.ACR.Registry, nil)

	// Metrics.
	reg := prometheus.NewRegistry()
	metrics := observability.NewMetrics(reg)

	mainSrv := &http.Server{Addr: cfg.Server.Addr, Handler: handler}
	metricsSrv := &http.Server{Addr: cfg.Server.MetricsAddr, Handler: metrics.Handler()}
	return mainSrv, metricsSrv, nil
}

// BuildWithBackends wires config into production servers with REAL backends (JWKS, Azure Blob,
// Valkey, ClickHouse, ACR). It validates required production config fields BEFORE constructing
// any live client, ensuring unit tests can verify config validation without hitting the network.
//
// Returns main server, metrics server, cleanup func, and error.
func BuildWithBackends(ctx context.Context, cfg config.Config) (*http.Server, *http.Server, func(), error) {
	// VALIDATE-FIRST: Check required production fields before constructing live clients.
	// This allows unit tests to exercise validation logic without network calls.
	if cfg.Auth.JWKSURL == "" {
		return nil, nil, nil, fmt.Errorf("production config: Auth.JWKSURL is required")
	}
	if cfg.Staging.BlobAccountURL == "" {
		return nil, nil, nil, fmt.Errorf("production config: Staging.BlobAccountURL is required")
	}
	if cfg.Staging.ValkeyAddr == "" {
		return nil, nil, nil, fmt.Errorf("production config: Staging.ValkeyAddr is required")
	}
	if cfg.Audit.ClickHouseDSN == "" {
		return nil, nil, nil, fmt.Errorf("production config: Audit.ClickHouseDSN is required")
	}
	if cfg.ACR.Registry == "" {
		return nil, nil, nil, fmt.Errorf("production config: ACR.Registry is required")
	}

	// Parse gate timeout
	gateTimeout, err := time.ParseDuration(cfg.Server.GateTimeout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse gate timeout %q: %w", cfg.Server.GateTimeout, err)
	}

	// --- LIVE BACKENDS (network calls below) ---

	// Create cancellable context for JWKS refresh goroutine
	bctx, cancel := context.WithCancel(ctx)

	// Track opened resources for cleanup on error
	var closers []func()
	fail := func(e error) (*http.Server, *http.Server, func(), error) {
		cancel()
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
		return nil, nil, nil, e
	}

	// Auth: Entra ID JWKS keyfunc + JWT authenticator (uses bctx for background refresh)
	keyfunc, err := auth.NewEntraKeyfunc(bctx, cfg.Auth.JWKSURL)
	if err != nil {
		return fail(fmt.Errorf("create JWKS keyfunc: %w", err))
	}
	authn := auth.NewJWTAuthenticator(cfg.Auth.Issuer, cfg.Auth.Audience, keyfunc)

	// Staging: Azure Blob + Valkey session store
	blobStore, err := staging.NewAzureBlobStoreWithCredential(cfg.Staging.BlobAccountURL, cfg.Staging.BlobContainer)
	if err != nil {
		return fail(fmt.Errorf("create blob store: %w", err))
	}
	sessionStore, err := staging.NewValkeySessionStore(cfg.Staging.ValkeyAddr)
	if err != nil {
		return fail(fmt.Errorf("create session store: %w", err))
	}
	store := staging.New(blobStore, sessionStore, generatePushID)

	// Audit: ClickHouse writer + auditor + reader
	auditWriter, err := audit.NewClickHouseWriter(cfg.Audit.ClickHouseDSN)
	if err != nil {
		return fail(fmt.Errorf("create audit writer: %w", err))
	}
	// Track writer for cleanup (cast to access Close method)
	writerCloser, ok := auditWriter.(interface{ Close() error })
	if ok {
		closers = append(closers, func() { writerCloser.Close() })
	}

	auditor := audit.NewAuditor(auditWriter, cfg.Audit.QueueSize, func(err error) {
		// TODO(observability): log dropped audit events
		_ = err
	})
	closers = append(closers, func() { auditor.Close() })

	reportsReader, err := audit.NewClickHouseReader(cfg.Audit.ClickHouseDSN)
	if err != nil {
		return fail(fmt.Errorf("create audit reader: %w", err))
	}
	closers = append(closers, func() { reportsReader.Close() })

	// ACR pusher with managed identity credentials
	pusher, err := acr.NewACRPusherWithCredential(cfg.ACR.Registry)
	if err != nil {
		return fail(fmt.Errorf("create ACR pusher: %w", err))
	}

	// Policies + engine
	trivyPolicy := trivy.New(trivy.NewExecRunner("trivy"), cfg.Trivy.SeverityThreshold)
	basePolicy := baseimage.New(cfg.BaseImage.AllowedIDs)
	engine := policy.NewEngine(trivyPolicy, basePolicy)

	// Router + pool
	rt := router.New(engine)
	pool := router.NewPool(rt, cfg.Staging.ScanPoolSize)

	// Docker ingress handler with real backends
	outcome := &dockeringress.Outcome{
		Pusher:        pusher,
		ReportBaseURL: "/reports",
		Recorder:      auditor,
		IDGen:         generatePushID,
	}
	handler := dockeringress.NewHandler(authn, store, rt, outcome, cfg.ACR.Registry, reportsReader)
	handler.SetPool(pool)
	handler.SetGateTimeout(gateTimeout)
	handler.SetMaxUploadBytes(cfg.Server.MaxUploadBytes)

	// Metrics
	reg := prometheus.NewRegistry()
	metrics := observability.NewMetrics(reg)

	mainSrv := &http.Server{Addr: cfg.Server.Addr, Handler: handler}
	metricsSrv := &http.Server{Addr: cfg.Server.MetricsAddr, Handler: metrics.Handler()}

	// Build cleanup function: cancel JWKS context + close all resources (reverse order)
	cleanup := func() {
		cancel() // Stop JWKS background refresh
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	return mainSrv, metricsSrv, cleanup, nil
}

// generatePushID creates a random 16-byte hex ID for tracking push sessions.
func generatePushID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}
