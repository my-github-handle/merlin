package promote

import (
	"context"
	"fmt"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
)

// Promoter accepts a passed image for deferred publication to ACR. Implementations
// must return fast: the caller is a manifest PUT whose client is holding a 30s
// response-header deadline, which is the entire reason promotion is deferred.
type Promoter interface {
	Promote(ctx context.Context, j Job) error // enqueue only; returns fast
}

// DecisionFinalizer records the terminal outcome of a deferred promotion against
// the decision the handler already wrote.
//
// It takes the whole Job, not just a push ID, because the audit store is
// append-only: "updating" a decision means writing a NEW gate_decisions row, and a
// row needs repo/tag/digest/identity to be legible on the dashboard and to sort
// correctly under ORDER BY (image_digest, ts).
type DecisionFinalizer interface {
	FinalizePromotion(ctx context.Context, j Job, ok bool, errDetail string)
}

// QueuePromoter adapts a Queue to Promoter. Enqueue is the whole implementation:
// the point of the hand-off is that nothing else happens on the request path.
type QueuePromoter struct{ Queue Queue }

// Promote enqueues the job for the worker to pick up.
func (p QueuePromoter) Promote(ctx context.Context, j Job) error {
	return p.Queue.Enqueue(ctx, j)
}

// DecisionRecorder is the append-only audit sink. audit.Auditor satisfies it; it is
// declared here (rather than imported from ingress/docker) so this package does not
// depend on the HTTP ingress.
type DecisionRecorder interface {
	Record(ctx context.Context, d audit.Decision, findings []policy.Finding)
}

// AuditFinalizer resolves promotion outcomes against the append-only audit store.
//
// There is no UPDATE path: gate_decisions is a plain MergeTree and the report
// lookup is `WHERE push_id = ? ORDER BY ts DESC LIMIT 1`
// (internal/audit/dashboard_queries.go:77), so a second row written under the same
// push_id becomes the authoritative one for the report page at read time. No
// argMax rewrite and no schema change are needed.
//
// Only TERMINAL FAILURES are written. A row per success would double every row in
// gate_decisions, inflating the totals and pass rate in DecisionStatsSince and
// listing every image twice in ImagesPage. Success is already the claim the
// handler's 201 row makes, so silence confirms it; the extra row exists precisely
// to contradict it.
//
// The failure row's shape is the one the synchronous path already used for this
// exact case (internal/ingress/docker/outcome.go: gate passed, ACR push failed):
// Passed=false with InfraError=true, so it is counted as an incomplete gate rather
// than a policy rejection, and ErrorDetail carries the operator-facing cause.
type AuditFinalizer struct {
	Recorder DecisionRecorder // nil disables finalization (hermetic tests)
}

// FinalizePromotion writes the contradicting row when a promotion is abandoned.
func (f AuditFinalizer) FinalizePromotion(ctx context.Context, j Job, ok bool, errDetail string) {
	if f.Recorder == nil || ok {
		return
	}
	f.Recorder.Record(ctx, audit.Decision{
		PushID:   j.PushID,
		Repo:     j.Repo,
		Tag:      j.Tag,
		Digest:   j.Digest,
		Identity: j.Identity,
		// Not a policy rejection: the gate passed. InfraError is what distinguishes
		// "we never published it" from "we refused to".
		Passed:      false,
		InfraError:  true,
		ErrorDetail: fmt.Sprintf("acr promotion abandoned after %d attempts: %s", j.Attempts, errDetail),
	}, nil)
}

// sleepCtx sleeps for d unless ctx is canceled first. It reports whether the full
// sleep elapsed, so a canceled worker stops polling instead of finishing its nap.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
