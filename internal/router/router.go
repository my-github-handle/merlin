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

// Outcome acts on a gate verdict in the way appropriate to the source.
type Outcome interface {
	Apply(ctx context.Context, req GateRequest, res policy.Result, gateErr error) error
}

// Router drives the trigger-agnostic gate core.
type Router struct {
	engine *policy.Engine
}

// New builds a router over the given policy engine.
func New(engine *policy.Engine) *Router {
	return &Router{engine: engine}
}

// Gate runs the policy engine and hands the result (and any infra error) to the
// outcome adapter. The infra error is surfaced via the outcome, not returned, so
// the adapter decides how to respond to the client.
func (r *Router) Gate(ctx context.Context, req GateRequest, outcome Outcome) error {
	res, gateErr := r.engine.Run(ctx, req.Image)
	return outcome.Apply(ctx, req, res, gateErr)
}
