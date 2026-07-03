// Package docker is the Docker Registry V2 ingress + outcome adapter.
package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/audit"
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

// DecisionRecorder is a non-blocking audit recorder for gate decisions.
// audit.Auditor satisfies this interface.
type DecisionRecorder interface {
	Record(ctx context.Context, d audit.Decision, findings []policy.Finding)
}

// Outcome is the Docker outcome adapter: push-or-reject the synchronous push.
// It holds only read-only configuration (ReportBaseURL + Recorder + IDGen), so a
// single Outcome is safe to share across concurrent requests: Apply builds and
// returns the Decision request-locally and stashes no per-request state. The ACR
// Pusher is supplied per request (it is the resolved tenant's pusher), so a shared
// Outcome can fan pushes out to different tenant registries.
type Outcome struct {
	ReportBaseURL string
	Recorder      DecisionRecorder // optional: nil skips audit recording (for hermetic tests)
	IDGen         func() string    // optional: generates unique PushID; defaults to generatePushID if nil
}

// Apply turns a gate result (and any infra error) into the Decision the HTTP
// handler renders, performing the ACR push as a side effect on pass and recording
// the decision (and findings) to the audit store if a Recorder is configured. The
// Decision is returned to the caller, not stored on the Outcome.
func (o *Outcome) Apply(ctx context.Context, pusher acr.Pusher, req router.GateRequest, res policy.Result, gateErr error) (Decision, error) {
	// The report is served by GET /reports/<push_id> from the audit store (findings
	// are keyed by push_id), so the report URL MUST use the same push_id that the
	// decision is recorded under — not the image digest. Generate it once here and
	// thread it through both the URL and the audit record.
	idGen := o.IDGen
	if idGen == nil {
		idGen = generatePushID
	}
	pushID := idGen()
	reportURL := fmt.Sprintf("%s/%s", o.ReportBaseURL, pushID)

	if gateErr != nil {
		o.recordDecision(ctx, pushID, req, res, false)
		return Decision{StatusCode: 500, Summary: "scan could not complete", ReportURL: reportURL, InfraError: true}, nil
	}
	summary := router.SummarizeResult(res)
	if !res.Passed {
		o.recordDecision(ctx, pushID, req, res, false)
		return Decision{StatusCode: 400, Summary: summary, ReportURL: reportURL}, nil
	}
	if err := pusher.Push(ctx, req.Image.OCIPath, req.Target); err != nil {
		o.recordDecision(ctx, pushID, req, res, false)
		return Decision{StatusCode: 502, Summary: "passed but ACR push failed", ReportURL: reportURL, InfraError: true}, fmt.Errorf("acr push: %w", err)
	}
	o.recordDecision(ctx, pushID, req, res, true)
	return Decision{StatusCode: 201, Summary: summary, ReportURL: reportURL}, nil
}

// recordDecision records the gate decision to the audit store if Recorder is
// configured, under the given pushID (shared with the report URL).
func (o *Outcome) recordDecision(ctx context.Context, pushID string, req router.GateRequest, res policy.Result, passed bool) {
	if o.Recorder == nil {
		return
	}

	// Collect failed policies and their reasons
	var failedPolicies []string
	var reasons []string
	for name, verdict := range res.Verdicts {
		if !verdict.Passed {
			failedPolicies = append(failedPolicies, name)
			reasons = append(reasons, verdict.Reasons...)
		}
	}

	decision := audit.Decision{
		PushID:         pushID,
		Repo:           req.Image.Repo,
		Tag:            req.Image.Tag,
		Digest:         req.Image.Digest,
		Identity:       req.Identity,
		Passed:         passed,
		FailedPolicies: failedPolicies,
		Reasons:        reasons,
		BaseImageID:    "", // not directly available; leave empty for now
		TrivyDBVersion: res.TrivyDBVersion,
		DurationMS:     0, // not measured; acceptable to leave 0
	}

	if res.Age != nil && res.Age.Known {
		decision.ImageCreated = res.Age.Created
		decision.ImageAgeDays = clampUint16(res.Age.AgeDays)
		decision.ImageAgeThresholdDays = clampUint16(res.Age.ThresholdDays)
	}

	o.Recorder.Record(ctx, decision, res.Findings)
}

// generatePushID generates a unique push ID using crypto/rand.
func generatePushID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a deterministic but unique-enough value
		return fmt.Sprintf("push-%d", len(b))
	}
	return hex.EncodeToString(b)
}

// clampUint16 converts a non-negative day count to uint16, saturating at the max
// (an age past ~179 years is not a meaningful distinction for the audit row).
func clampUint16(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 65535 {
		return 65535
	}
	return uint16(n)
}
