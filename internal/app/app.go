// Package app wires Merlin's components into runnable HTTP servers.
package app

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/golang-jwt/jwt/v5"
	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/config"
	dockeringress "github.com/merlin-gate/merlin/internal/ingress/docker"
	"github.com/merlin-gate/merlin/internal/observability"
	"github.com/merlin-gate/merlin/internal/policies/baseimage"
	"github.com/merlin-gate/merlin/internal/policies/trivy"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
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
