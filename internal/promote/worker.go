package promote

import (
	"context"
	"fmt"
	"log"
	"os"
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
	// Localize rebuilds the job's OCI layout on THIS pod and returns the new
	// (ociPath, scratchDir). It is called only when Job.OCIPath is absent from the
	// local filesystem.
	//
	// It exists because scratch is an emptyDir — per POD — while the queue is one
	// shared Valkey list and the chart runs replicaCount: 2. Claim is an unscoped
	// LPOP, so roughly half of all jobs land on the pod that did NOT assemble the
	// image. Without a rebuild those jobs spend their whole attempt budget pushing a
	// directory that was never on this filesystem and are retired, after the client
	// was already told 201 — an approved image that is silently never published.
	//
	// The rebuild is possible because the staged blobs live in the SHARED blob store
	// and their ref-counts are released by Cleanup, which has not run yet.
	//
	// Nil skips the check entirely (hermetic tests, single-replica dev), so the
	// stat cost and the fake paths in unit tests are both avoided.
	Localize func(ctx context.Context, j Job) (ociPath, scratchDir string, err error)
	// Cleanup releases the job's scratch dir and staged blob ref-counts. It runs
	// only when no retry will follow — see handle.
	Cleanup func(ctx context.Context, j Job) error
	// Metrics receives promotion telemetry. ObserveACRPush is reached through an
	// optional interface assertion (see observeACRPush) so existing fakes that only
	// implement ObservePromoteDuration keep compiling.
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

	// Make the layout local before pushing. A failure here is weather, not
	// configuration — the blobs may still be mid-upload or the store briefly
	// unreachable — so it takes the normal retry path.
	if lj, ok := w.localize(ctx, j); ok {
		j = lj
	} else {
		return
	}

	start := time.Now()
	err = pusher.Push(ctx, j.OCIPath, j.Target)
	if w.Metrics != nil {
		// Observed on failure too: a slow push that ends in an error still consumed
		// the phase, and excluding it would understate promotion latency exactly when
		// ACR is the problem.
		w.Metrics.ObservePromoteDuration(time.Since(start).Seconds())
	}
	// This is the REAL ACR push in the deployed configuration — the gate's publish
	// step only enqueued this job — so the push counter is incremented here, by
	// registry and cause. Retries count separately on purpose: three attempts
	// against a revoked credential are three auth failures, and collapsing them
	// would hide how long the condition persisted.
	w.observeACRPush(acr.RegistryFromTarget(j.Target), string(acr.ClassifyPushError(err)))
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

// localize returns the job with its OCI layout guaranteed present on this pod. It
// reports false when the job has already been failed/retired and handle must stop.
//
// The rebuilt paths REPLACE the job's own: the origin pod's ScratchDir does not
// exist here, so cleaning it up would be a no-op that leaks the layout this pod
// just built. (The origin pod's copy is reclaimed by the scratch sweep instead —
// nothing else can reach it.)
func (w *Worker) localize(ctx context.Context, j Job) (Job, bool) {
	if w.Localize == nil {
		return j, true
	}
	if _, err := os.Stat(j.OCIPath); err == nil {
		return j, true // assembled by this pod; nothing to do
	}
	ociPath, scratchDir, err := w.Localize(ctx, j)
	if err != nil {
		w.fail(ctx, j, fmt.Errorf("rebuild oci layout for %s: %w", j.Target, err))
		return j, false
	}
	j.OCIPath, j.ScratchDir = ociPath, scratchDir
	return j, true
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

// observeACRPush records one real ACR push attempt. Optional-interface so the
// many test fakes that only implement ObservePromoteDuration keep compiling.
func (w *Worker) observeACRPush(registry, result string) {
	if w.Metrics == nil {
		return
	}
	if m, ok := w.Metrics.(interface {
		ObserveACRPush(registry, result string)
	}); ok {
		m.ObserveACRPush(registry, result)
	}
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
