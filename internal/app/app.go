// Package app wires Merlin's components into runnable HTTP servers.
package app

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/config"
	dockeringress "github.com/merlin-gate/merlin/internal/ingress/docker"
	"github.com/merlin-gate/merlin/internal/observability"
	"github.com/merlin-gate/merlin/internal/policies/baseimage"
	"github.com/merlin-gate/merlin/internal/policies/trivy"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/golang-jwt/jwt/v5"
)

// Build wires config into the V2 server and the metrics server.
func Build(cfg config.Config) (*http.Server, *http.Server, error) {
	// Policies + engine.
	trivyPolicy := trivy.New(trivy.NewExecRunner("trivy"), cfg.Trivy.SeverityThreshold)
	basePolicy := baseimage.New(cfg.BaseImage.AllowedIDs)
	engine := policy.NewEngine(trivyPolicy, basePolicy)

	// Auth — in production keyfunc is JWKS-backed; here a stub keyfunc is replaced
	// at deploy time. Build must not require network, so use a placeholder keyfunc.
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
