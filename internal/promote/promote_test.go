package promote

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
)

// recordingAuditor captures what AuditFinalizer writes to the audit store.
type recordingAuditor struct {
	mu   sync.Mutex
	rows []audit.Decision
}

func (r *recordingAuditor) Record(_ context.Context, d audit.Decision, _ []policy.Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = append(r.rows, d)
}

func (r *recordingAuditor) written() []audit.Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Decision(nil), r.rows...)
}

// TestAuditFinalizerWritesNothingOnSuccess is the load-bearing half of the
// append-only design. gate_decisions has no UPDATE path, so a success row would be
// an ADDITIONAL row for a push that already has one: DecisionStatsSince would count
// the push twice (skewing totals and pass rate) and ImagesPage would list the image
// twice. The handler's 201 row already asserts success; silence confirms it.
func TestAuditFinalizerWritesNothingOnSuccess(t *testing.T) {
	rec := &recordingAuditor{}
	AuditFinalizer{Recorder: rec}.FinalizePromotion(context.Background(),
		Job{PushID: "p1", Repo: "app", Digest: "sha256:aa"}, true, "")

	if n := len(rec.written()); n != 0 {
		t.Errorf("audit rows written on success = %d, want 0 (every push would be double-counted)", n)
	}
}

// TestAuditFinalizerContradictsTheSuccessRowOnFailure pins the shape of the failure
// row. DecisionHeaderByPush reads `WHERE push_id = ? ORDER BY ts DESC LIMIT 1`
// (internal/audit/dashboard_queries.go:77), so a second row under the SAME push_id
// becomes the authoritative one for the report page — which only works if the row
// carries the same push_id and enough image identity to be legible.
func TestAuditFinalizerContradictsTheSuccessRowOnFailure(t *testing.T) {
	rec := &recordingAuditor{}
	job := Job{
		PushID: "p1", Repo: "c3aiops", Tag: "v1", Digest: "sha256:aa",
		Identity: "ci@example.com", Attempts: 3,
	}
	AuditFinalizer{Recorder: rec}.FinalizePromotion(context.Background(), job, false, "acr push: 401 unauthorized")

	rows := rec.written()
	if len(rows) != 1 {
		t.Fatalf("audit rows written on failure = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.PushID != "p1" {
		t.Errorf("PushID = %q, want p1; the report lookup keys on push_id and would never find this row", got.PushID)
	}
	// Without these the dashboard renders a blank row and the MergeTree sort key
	// (image_digest, ts) puts it nowhere useful.
	if got.Repo != "c3aiops" || got.Tag != "v1" || got.Digest != "sha256:aa" || got.Identity != "ci@example.com" {
		t.Errorf("image identity incomplete on the failure row: %+v", got)
	}
	// InfraError, not a policy rejection: the gate PASSED and we failed to publish.
	// This is the same distinction the synchronous path already makes for a failed
	// ACR push, and the reject-reason dashboard query depends on it.
	if !got.InfraError {
		t.Error("InfraError = false; an unpublished image would be reported as a policy rejection")
	}
	if got.Passed {
		t.Error("Passed = true on a promotion that never reached ACR")
	}
	if len(got.FailedPolicies) != 0 || len(got.Reasons) != 0 {
		t.Errorf("failure row carries policy verdicts (%v / %v); it would skew the top-reject-reasons panel",
			got.FailedPolicies, got.Reasons)
	}
	if !strings.Contains(got.ErrorDetail, "401 unauthorized") {
		t.Errorf("ErrorDetail = %q, want the underlying cause; otherwise the row is unexplainable", got.ErrorDetail)
	}
	if !strings.Contains(got.ErrorDetail, "3 attempts") {
		t.Errorf("ErrorDetail = %q, want the attempt count (distinguishes a flaky ACR from a hard failure)", got.ErrorDetail)
	}
}

// TestAuditFinalizerWithoutRecorderIsInert keeps hermetic wiring (and any
// deployment with the audit store disabled) from panicking on every promotion.
func TestAuditFinalizerWithoutRecorderIsInert(t *testing.T) {
	AuditFinalizer{}.FinalizePromotion(context.Background(), Job{PushID: "p1"}, false, "boom")
}

// TestQueuePromoterEnqueues pins that Promote does nothing but hand off. Anything
// slower on this path defeats the purpose: the caller is a manifest PUT whose client
// is holding a 30s response-header deadline.
func TestQueuePromoterEnqueues(t *testing.T) {
	q := NewMemoryQueue()
	if err := (QueuePromoter{Queue: q}).Promote(context.Background(), Job{PushID: "p1"}); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	got, ok, err := q.Claim(context.Background())
	if err != nil || !ok {
		t.Fatalf("Claim after Promote: ok=%v err=%v", ok, err)
	}
	if got.PushID != "p1" {
		t.Errorf("claimed %q, want p1", got.PushID)
	}
}
