package promote

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
)

// Worker drains the promotion queue. Run blocks until ctx is canceled.
//
// Run is safe to call from several goroutines against one Worker: all per-job state
// lives on the stack, and Claim hands each job to exactly one caller. Promotion is
// network-bound rather than memory-bound, so unlike the scan pool it does not need
// a memory-derived concurrency cap.
type Worker struct {
	Queue Queue
	// Pushers resolves the tenant's ACR pusher from the tenant PREFIX carried on
	// the Job — NOT from the repo. Tenants are keyed by host prefix
	// (internal/tenant/resolver.go:26, PrefixFromHost), and under the multi-ACR
	// config two tenants can host the same repo name, so a repo-keyed lookup would
	// publish to the wrong registry.
	Pushers  func(tenantPrefix string) (acr.Pusher, error)
	Recorder DecisionFinalizer
	// Cleanup releases the job's scratch dir and staged blob ref-counts. It runs
	// only when no retry will follow — see handle.
	Cleanup func(ctx context.Context, j Job) error
	Metrics interface{ ObservePromoteDuration(float64) }
	// MaxAttempts bounds pushes per job. Zero means defaultMaxAttempts. Without a
	// bound, a permanently failing push (revoked credentials, deleted repo)
	// re-queues forever while holding its OCI layout on local disk.
	MaxAttempts uint8
	// PollInterval is the idle sleep between Claim attempts. Zero means
	// defaultPollInterval.
	PollInterval time.Duration
	// RecoverAfter is how old a claim must be before this worker treats it as
	// abandoned. Zero means defaultRecoverAfter.
	//
	// It must NOT default to zero-as-in-"reclaim everything": the chart runs
	// replicaCount: 2, so a starting worker that reclaimed every outstanding claim
	// would re-promote whatever its sibling is pushing at that moment — a duplicate
	// push, and for a tag target a tag that moves backward (see Queue.Recover).
	// Tests that want the reclaim-everything behaviour set it explicitly.
	RecoverAfter time.Duration
}

const (
	defaultMaxAttempts   = 3
	defaultPollInterval  = 200 * time.Millisecond
	defaultRecoverAfter  = 15 * time.Minute
	claimErrorBackoff    = time.Second
	recoverErrorInterval = time.Minute
)

func (w *Worker) maxAttempts() uint8 {
	if w.MaxAttempts == 0 {
		return defaultMaxAttempts
	}
	return w.MaxAttempts
}

func (w *Worker) pollInterval() time.Duration {
	if w.PollInterval == 0 {
		return defaultPollInterval
	}
	return w.PollInterval
}

// Run drains the queue until ctx is canceled.
//
// The ctx passed here must be the PROCESS lifetime context, never a request
// context: the HTTP handler that enqueued the job has already answered its client,
// so a request-scoped context would be canceled immediately and every promotion
// would fail with context.Canceled.
func (w *Worker) Run(ctx context.Context) {
	recoverEvery := w.RecoverAfter
	if recoverEvery <= 0 {
		recoverEvery = recoverErrorInterval
	}
	nextRecover := time.Now() // recover once at start, then on this cadence
	for {
		if ctx.Err() != nil {
			return
		}
		if !time.Now().Before(nextRecover) {
			w.recover(ctx)
			nextRecover = time.Now().Add(recoverEvery)
		}
		j, ok, err := w.Queue.Claim(ctx)
		if err != nil {
			// Do not treat a Claim error as an empty queue: backing off hard keeps a
			// Valkey outage from becoming a tight loop against a dying dependency.
			log.Printf("promote: claim failed: %v", err)
			if !sleepCtx(ctx, claimErrorBackoff) {
				return
			}
			continue
		}
		if !ok {
			if !sleepCtx(ctx, w.pollInterval()) {
				return
			}
			continue
		}
		w.handle(ctx, j)
	}
}

// recover re-queues claims older than RecoverAfter — work abandoned by a worker
// that died mid-promotion. Errors are logged, not fatal: a failed recovery sweep
// leaves the jobs claimed, and the next sweep tries again.
func (w *Worker) recover(ctx context.Context) {
	after := w.RecoverAfter
	if after < 0 {
		after = defaultRecoverAfter
	}
	jobs, err := w.Queue.Recover(ctx, after)
	if err != nil {
		log.Printf("promote: recover abandoned claims: %v", err)
	}
	if len(jobs) > 0 {
		log.Printf("promote: recovered %d abandoned promotion(s)", len(jobs))
	}
}

// handle promotes one job.
//
// The ordering here is the whole correctness argument:
//
//   - On success, Ack comes BEFORE Cleanup. Acking first risks leaking a scratch
//     dir if the process dies in between; cleaning first risks the job being
//     recovered and re-promoted from a directory that no longer exists, which
//     burns its whole attempt budget on a doomed retry. A leaked directory is
//     visible and sweepable; a doomed retry loses a published image's record.
//
//   - On a retryable failure the scratch dir is LEFT ALONE. Deleting the OCI
//     layout makes the retry structurally impossible.
//
//   - Re-enqueue comes BEFORE Ack. Acking first risks losing the job entirely if
//     the process dies in between (an approved image never published — the one
//     outcome this package exists to prevent); enqueueing first risks the job
//     existing twice, which is a duplicate push and therefore harmless. Queue
//     documents this as deliberately at-least-once.
func (w *Worker) handle(ctx context.Context, j Job) {
	pusher, err := w.Pushers(j.Tenant)
	if err != nil {
		// An unresolvable tenant prefix is configuration, not weather: no retry can
		// fix it, and there is no safe fallback — publishing to any other tenant's
		// registry is worse than not publishing at all.
		w.retire(ctx, j, fmt.Errorf("resolve pusher for tenant %q: %w", j.Tenant, err))
		return
	}
	j.Attempts++

	start := time.Now()
	err = pusher.Push(ctx, j.OCIPath, j.Target)
	if w.Metrics != nil {
		// Observed on failure too: a slow push that ends in an error still consumed
		// the phase, and excluding it would understate promotion latency exactly when
		// ACR is the problem.
		w.Metrics.ObservePromoteDuration(time.Since(start).Seconds())
	}
	if err != nil {
		w.fail(ctx, j, fmt.Errorf("acr push: %w", err))
		return
	}

	w.finalize(ctx, j, true, "")
	if aerr := w.Queue.Ack(ctx, j.PushID); aerr != nil {
		// The image IS published. Log and clean up anyway: a failed Ack means the job
		// may be recovered and re-pushed, which is wasted bandwidth rather than a
		// correctness problem.
		log.Printf("promote %s: published but ack failed (may be re-pushed): %v", j.PushID, aerr)
	}
	w.cleanup(ctx, j)
}

// fail decides between retry and retirement. A job that has spent its budget is
// retired; anything else goes back to the head of the queue with its scratch dir
// intact.
func (w *Worker) fail(ctx context.Context, j Job, cause error) {
	if j.Attempts >= w.maxAttempts() {
		w.retire(ctx, j, cause)
		return
	}
	log.Printf("promote %s: attempt %d/%d failed, requeueing: %v",
		j.PushID, j.Attempts, w.maxAttempts(), cause)
	if eerr := w.Queue.Enqueue(ctx, j); eerr != nil {
		// The claim is deliberately NOT acked here. Leaving it claimed means Recover
		// picks the job up later; acking it would drop an approved image on the floor.
		log.Printf("promote %s: requeue failed, leaving claim for recovery: %v", j.PushID, eerr)
		return
	}
	if aerr := w.Queue.Ack(ctx, j.PushID); aerr != nil {
		log.Printf("promote %s: requeued but ack failed (may be promoted twice): %v", j.PushID, aerr)
	}
}

// retire abandons a job permanently: record why, release the scratch dir (no retry
// will follow, so holding it leaks disk), and drop the claim.
func (w *Worker) retire(ctx context.Context, j Job, cause error) {
	log.Printf("promote %s: abandoning after %d attempt(s): %v", j.PushID, j.Attempts, cause)
	w.finalize(ctx, j, false, cause.Error())
	if aerr := w.Queue.Ack(ctx, j.PushID); aerr != nil {
		log.Printf("promote %s: retired but ack failed (will be retried): %v", j.PushID, aerr)
	}
	w.cleanup(ctx, j)
}

func (w *Worker) finalize(ctx context.Context, j Job, ok bool, detail string) {
	if w.Recorder == nil {
		return
	}
	w.Recorder.FinalizePromotion(ctx, j, ok, detail)
}

func (w *Worker) cleanup(ctx context.Context, j Job) {
	if w.Cleanup == nil {
		return
	}
	if cerr := w.Cleanup(ctx, j); cerr != nil {
		log.Printf("promote %s: cleanup failed (scratch dir and blob refs leaked): %v", j.PushID, cerr)
	}
}
