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
type Outcome struct {
	Pusher        acr.Pusher
	ReportBaseURL string
	last          Decision
}

func (o *Outcome) Last() Decision { return o.last }

func (o *Outcome) Apply(ctx context.Context, req router.GateRequest, res policy.Result, gateErr error) error {
	reportURL := fmt.Sprintf("%s/%s", o.ReportBaseURL, req.Image.Digest)
	if gateErr != nil {
		o.last = Decision{StatusCode: 500, Summary: "scan could not complete", ReportURL: reportURL, InfraError: true}
		return nil
	}
	summary := router.SummarizeResult(res)
	if !res.Passed {
		o.last = Decision{StatusCode: 400, Summary: summary, ReportURL: reportURL}
		return nil
	}
	if err := o.Pusher.Push(ctx, req.Image.OCIPath, req.Target); err != nil {
		o.last = Decision{StatusCode: 502, Summary: "passed but ACR push failed", ReportURL: reportURL, InfraError: true}
		return fmt.Errorf("acr push: %w", err)
	}
	o.last = Decision{StatusCode: 201, Summary: summary, ReportURL: reportURL}
	return nil
}
