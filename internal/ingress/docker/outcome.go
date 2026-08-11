// Package docker is the Docker Registry V2 ingress + outcome adapter.
package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

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

// MetricsObserver receives per-push telemetry. observability.Metrics satisfies
// it. All methods must be safe for concurrent use (Apply runs per request).
type MetricsObserver interface {
	ObservePush(passed bool)
	ObserveACRPush(ok bool)
	ObserveScanDuration(seconds float64)
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
	Metrics       MetricsObserver  // optional: nil skips metric observation (for hermetic tests)
}

// Apply turns a gate result (and any infra error) into the Decision the HTTP
// handler renders, performing the ACR push as a side effect on pass and recording
// the decision (and findings) to the audit store if a Recorder is configured. The
// Decision is returned to the caller, not stored on the Outcome.
func (o *Outcome) Apply(ctx context.Context, pusher acr.Pusher, req router.GateRequest, res policy.Result, gateErr error, scanDur time.Duration) (Decision, error) {
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

	// Observe the scan duration once per decision (it is the same regardless of the
	// pass/reject/infra branch below). ClickHouse-backed latency percentiles read
	// DurationMS on the recorded decision; the histogram feeds /metrics scrapers.
	durMS := uint32(scanDur.Milliseconds())
	if o.Metrics != nil {
		o.Metrics.ObserveScanDuration(scanDur.Seconds())
	}

	if gateErr != nil {
		// Infra failures must be countable and explainable: without the metric the
		// error rate is invisible in merlin_push_decisions_total, and without the
		// recorded detail the audit row is an unexplainable empty rejection.
		o.observePushError()
		if errors.Is(gateErr, router.ErrSaturated) {
			o.recordDecision(ctx, pushID, req, res, false, durMS, gateErr)
			return Decision{StatusCode: 503, Summary: "scan pool saturated, retry later", ReportURL: reportURL, InfraError: true}, nil
		}
		o.recordDecision(ctx, pushID, req, res, false, durMS, gateErr)
		return Decision{StatusCode: 500, Summary: "scan could not complete", ReportURL: reportURL, InfraError: true}, nil
	}
	if o.Metrics != nil {
		o.Metrics.ObservePush(res.Passed)
	}
	summary := router.SummarizeResult(res)
	if !res.Passed {
		o.recordDecision(ctx, pushID, req, res, false, durMS, nil)
		return Decision{StatusCode: 400, Summary: summary, ReportURL: reportURL}, nil
	}
	promoteStart := time.Now()
	err := pusher.Push(ctx, req.Image.OCIPath, req.Target)
	// Observed on failure too: a slow push that ends in an error still consumed the
	// client's window, and excluding those observations would understate the phase.
	o.observePromote(time.Since(promoteStart))
	if err != nil {
		if o.Metrics != nil {
			o.Metrics.ObserveACRPush(false)
		}
		// The scan PASSED; record the push as an infra failure (not a policy
		// rejection) with the ACR error so the report page can say so.
		o.recordDecision(ctx, pushID, req, res, false, durMS, fmt.Errorf("acr push: %w", err))
		return Decision{StatusCode: 502, Summary: "passed but ACR push failed", ReportURL: reportURL, InfraError: true}, fmt.Errorf("acr push: %w", err)
	}
	if o.Metrics != nil {
		o.Metrics.ObserveACRPush(true)
	}
	o.recordDecision(ctx, pushID, req, res, true, durMS, nil)
	return Decision{StatusCode: 201, Summary: summary, ReportURL: reportURL}, nil
}

// observePushError bumps the push-decision counter with an "error" outcome when
// the metrics sink supports it. Optional-interface so existing MetricsObserver
// fakes keep compiling.
func (o *Outcome) observePushError() {
	if m, ok := o.Metrics.(interface{ ObservePushError() }); ok {
		m.ObservePushError()
	}
}

// observePromote records how long the ACR push took — the last phase of the
// blocked manifest-PUT window. Optional-interface for the same reason as
// observePushError: existing MetricsObserver fakes must keep compiling.
func (o *Outcome) observePromote(d time.Duration) {
	if o.Metrics == nil {
		return
	}
	if m, ok := o.Metrics.(interface{ ObservePromoteDuration(float64) }); ok {
		m.ObservePromoteDuration(d.Seconds())
	}
}

// recordDecision records the gate decision to the audit store if Recorder is
// configured, under the given pushID (shared with the report URL). infraErr,
// when non-nil, marks the row as an incomplete gate (NOT a policy rejection)
// and persists the cause — otherwise a timed-out or crashed scan is
// indistinguishable from a reject in the audit store and on the dashboard.
func (o *Outcome) recordDecision(ctx context.Context, pushID string, req router.GateRequest, res policy.Result, passed bool, durMS uint32, infraErr error) {
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
		PushID:           pushID,
		Repo:             req.Image.Repo,
		Tag:              req.Image.Tag,
		Digest:           req.Image.Digest,
		Identity:         req.Identity,
		Passed:           passed,
		FailedPolicies:   failedPolicies,
		Reasons:          reasons,
		BaseImageID:      "", // not directly available; leave empty for now
		ScannerDBVersion: res.ScannerDBVersion,
		DurationMS:       durMS,
	}

	if res.Age != nil && res.Age.Known {
		decision.ImageCreated = res.Age.Created
		decision.ImageAgeDays = clampUint16(res.Age.AgeDays)
		decision.ImageAgeThresholdDays = clampUint16(res.Age.ThresholdDays)
		decision.ImageAgeKnown = true
	}

	if infraErr != nil {
		decision.InfraError = true
		decision.ErrorDetail = infraErr.Error()
	}

	o.Recorder.Record(ctx, decision, res.Findings)
}

// generatePushID generates a unique push ID using crypto/rand. The value must be
// unique AND parseable into the audit store's UUID column (32 hex chars), so the
// fallback derives from the wall clock rather than a constant.
func generatePushID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure: still unique per call and UUID-parseable.
		return fmt.Sprintf("%032x", uint64(time.Now().UnixNano()))
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
