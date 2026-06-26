package dashboard

import (
	"context"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
)

// DecisionRecorder mirrors dockeringress.DecisionRecorder. Declared here to avoid
// importing the ingress package (which would create an import cycle).
type DecisionRecorder interface {
	Record(ctx context.Context, d audit.Decision, findings []policy.Finding)
}

// TeeRecorder records to an inner recorder (the ClickHouse Auditor) and also
// publishes a live summary to the dashboard broadcaster. It implements
// DecisionRecorder, so it drops into Outcome.Recorder unchanged.
type TeeRecorder struct {
	inner DecisionRecorder
	b     *Broadcaster
}

// NewTeeRecorder wraps inner so each decision is both persisted and broadcast.
// inner may be nil (broadcast-only).
func NewTeeRecorder(inner DecisionRecorder, b *Broadcaster) *TeeRecorder {
	return &TeeRecorder{inner: inner, b: b}
}

func (t *TeeRecorder) Record(ctx context.Context, d audit.Decision, findings []policy.Finding) {
	if t.inner != nil {
		t.inner.Record(ctx, d, findings)
	}
	if t.b != nil {
		t.b.Publish(audit.DecisionSummary{
			PushID: d.PushID, Repo: d.Repo, Tag: d.Tag, Digest: d.Digest,
			Identity: d.Identity, Passed: d.Passed, Reasons: d.Reasons,
		})
	}
}
