// Package router decouples the gate core from ingress/outcome adapters.
package router

import (
	"context"

	"github.com/merlin-gate/merlin/internal/policy"
)

// GateRequest is a normalized request to gate an artifact, source-agnostic.
type GateRequest struct {
	Source   string
	Identity string
	Image    policy.StagedImage
	Target   string
}

// Router drives the trigger-agnostic gate core.
type Router struct {
	engine *policy.Engine
}

// New builds a router over the given policy engine.
func New(engine *policy.Engine) *Router {
	return &Router{engine: engine}
}

// Gate runs the policy engine and returns the gate result together with any
// infra error from the engine. The router is outcome-agnostic: the caller (the
// source-specific handler) decides how to act on the result. Returning the
// result by value keeps the decision request-local — there is no shared state.
func (r *Router) Gate(ctx context.Context, req GateRequest) (policy.Result, error) {
	return r.engine.Run(ctx, req.Image)
}
