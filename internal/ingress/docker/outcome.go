// Package docker is the Docker Registry V2 ingress + outcome adapter.
package docker

import (
	"context"
	"fmt"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
)

// Decision is what the HTTP handler renders for a manifest PUT.
type Decision struct {
	StatusCode int
	Summary    string
	ReportURL  string
	InfraError bool
}

// Outcome is the Docker outcome adapter: push-or-reject the synchronous push.
// It holds only read-only configuration (Pusher + ReportBaseURL), so a single
// Outcome is safe to share across concurrent requests: Apply builds and returns
// the Decision request-locally and stashes no per-request state.
type Outcome struct {
	Pusher        acr.Pusher
	ReportBaseURL string
}

// Apply turns a gate result (and any infra error) into the Decision the HTTP
// handler renders, performing the ACR push as a side effect on pass. The
// Decision is returned to the caller, not stored on the Outcome.
func (o *Outcome) Apply(ctx context.Context, req router.GateRequest, res policy.Result, gateErr error) (Decision, error) {
	reportURL := fmt.Sprintf("%s/%s", o.ReportBaseURL, req.Image.Digest)
	if gateErr != nil {
		return Decision{StatusCode: 500, Summary: "scan could not complete", ReportURL: reportURL, InfraError: true}, nil
	}
	summary := router.SummarizeResult(res)
	if !res.Passed {
		return Decision{StatusCode: 400, Summary: summary, ReportURL: reportURL}, nil
	}
	if err := o.Pusher.Push(ctx, req.Image.OCIPath, req.Target); err != nil {
		return Decision{StatusCode: 502, Summary: "passed but ACR push failed", ReportURL: reportURL, InfraError: true}, fmt.Errorf("acr push: %w", err)
	}
	return Decision{StatusCode: 201, Summary: summary, ReportURL: reportURL}, nil
}
