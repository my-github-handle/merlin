package promote

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
)

// faultQueue wraps a Queue and fails chosen operations.
//
// It exists because the worker's most consequential decisions are all in its
// error-handling branches — whether a failed requeue leaves the claim for Recover,
// whether a published-but-unacked job still gets cleaned up — and none of them are
// reachable through a Queue that always works. Seeding goes through the embedded
// Queue directly (fq.Queue.Enqueue) so a test's setup is not itself a fault.
type faultQueue struct {
	Queue

	mu               sync.Mutex
	enqueueErr       error
	ackErr           error
	claimErrOnce     error
	recoverErr       error
	claims           int
	acks             int
	enqueues         int
	recoverOlderThan []time.Duration
}

func (q *faultQueue) Enqueue(ctx context.Context, j Job) error {
	q.mu.Lock()
	q.enqueues++
	err := q.enqueueErr
	q.mu.Unlock()
	if err != nil {
		return err
	}
	return q.Queue.Enqueue(ctx, j)
}

func (q *faultQueue) Claim(ctx context.Context) (Job, bool, error) {
	q.mu.Lock()
	q.claims++
	err := q.claimErrOnce
	q.claimErrOnce = nil // fail once, then behave: the retry is what proves recovery
	q.mu.Unlock()
	if err != nil {
		return Job{}, false, err
	}
	return q.Queue.Claim(ctx)
}

func (q *faultQueue) Ack(ctx context.Context, pushID string) error {
	q.mu.Lock()
	q.acks++
	err := q.ackErr
	q.mu.Unlock()
	if err != nil {
		return err
	}
	return q.Queue.Ack(ctx, pushID)
}

func (q *faultQueue) Recover(ctx context.Context, olderThan time.Duration) ([]Job, error) {
	q.mu.Lock()
	q.recoverOlderThan = append(q.recoverOlderThan, olderThan)
	err := q.recoverErr
	q.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return q.Queue.Recover(ctx, olderThan)
}

func (q *faultQueue) counts() (claims, acks, enqueues int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.claims, q.acks, q.enqueues
}

func (q *faultQueue) windows() []time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]time.Duration(nil), q.recoverOlderThan...)
}

func newFaultQueue() *faultQueue { return &faultQueue{Queue: NewMemoryQueue()} }

// seed enqueues without going through the fault, so a test can inject an Enqueue
// failure that applies only to the worker's REQUEUE.
func (q *faultQueue) seed(t *testing.T, j Job) {
	t.Helper()
	if err := q.Queue.Enqueue(context.Background(), j); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestWorkerDefaultsAreTheDocumentedOnes pins the two zero-value defaults. Both are
// load-bearing and neither is exercised by a test that configures the worker:
// MaxAttempts bounds ACR pushes against a permanently failing target, and a zero
// PollInterval would make the idle loop a spin.
func TestWorkerDefaultsAreTheDocumentedOnes(t *testing.T) {
	if got := (&Worker{}).pollInterval(); got != defaultPollInterval {
		t.Errorf("zero PollInterval = %v, want %v (a zero sleep is a spin loop)", got, defaultPollInterval)
	}
	if got := (&Worker{}).maxAttempts(); got != defaultMaxAttempts {
		t.Errorf("zero MaxAttempts = %d, want %d", got, defaultMaxAttempts)
	}
	if got := (&Worker{MaxAttempts: 7}).maxAttempts(); got != 7 {
		t.Errorf("explicit MaxAttempts = %d, want 7", got)
	}

	// And the default is what the worker actually spends, not just what the helper
	// returns: a job on a permanently failing registry must stop at 3 pushes.
	q := newFaultQueue()
	pusher := &fakePusher{err: errors.New("acr 401 unauthorized")}
	fin := &fakeFinalizer{}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: fin,
		Cleanup:  func(context.Context, Job) error { return nil },
		// MaxAttempts deliberately unset.
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool { _, ok := fin.failed("p1"); return ok })

	if got := pusher.calls(); got != int(defaultMaxAttempts) {
		t.Errorf("push attempts with default budget = %d, want %d", got, defaultMaxAttempts)
	}
}

// TestWorkerBacksOffOnClaimErrorAndKeepsDraining pins that a Valkey blip is not
// mistaken for an empty queue. Treating a Claim error as "nothing to do" is
// survivable; the failure mode this guards is the opposite one — a tight loop
// hammering a dependency that is already failing.
func TestWorkerBacksOffOnClaimErrorAndKeepsDraining(t *testing.T) {
	q := newFaultQueue()
	q.claimErrOnce = errors.New("valkey: connection reset")
	pusher := &fakePusher{}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Cleanup:  func(context.Context, Job) error { return nil },
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	go w.Run(ctx)

	// The job is promoted only after the backoff elapses, and the whole point is that
	// it IS eventually promoted: a Claim error must not lose the job.
	waitFor2(t, 5*time.Second, func() bool { return pusher.calls() == 1 })
	if waited := time.Since(start); waited < claimErrorBackoff {
		t.Errorf("resumed after %v, want at least the %v backoff (a failing claim must not spin)",
			waited, claimErrorBackoff)
	}
	if claims, _, _ := q.counts(); claims < 2 {
		t.Errorf("claims = %d, want >= 2 (the worker gave up after one error)", claims)
	}
}

// TestWorkerStopsBackingOffWhenCanceled pins shutdown during the claim backoff: a
// worker asleep on a one-second timer must not outlive its context, or a rolling
// deploy waits on it for no reason.
func TestWorkerStopsBackingOffWhenCanceled(t *testing.T) {
	q := newFaultQueue()
	q.claimErrOnce = errors.New("valkey: connection refused")
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return &fakePusher{}, nil },
		Recorder: &fakeFinalizer{},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	waitFor(t, func() bool { claims, _, _ := q.counts(); return claims >= 1 })
	cancel()

	select {
	case <-done:
	case <-time.After(claimErrorBackoff / 2):
		t.Fatal("Run did not return promptly after cancel; it finished its backoff nap first")
	}
}

// TestWorkerSurvivesRecoverFailure pins that a failed recovery sweep is not fatal.
// The jobs stay claimed and the next sweep tries again; crashing the loop instead
// would strand every queued promotion behind one Valkey error.
func TestWorkerSurvivesRecoverFailure(t *testing.T) {
	q := newFaultQueue()
	q.recoverErr = errors.New("valkey: HGETALL failed")
	pusher := &fakePusher{}
	w := testWorker(&Worker{
		Queue:        q,
		Pushers:      func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder:     &fakeFinalizer{},
		Cleanup:      func(context.Context, Job) error { return nil },
		RecoverAfter: time.Hour,
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitFor(t, func() bool { return pusher.calls() == 1 })
	if len(q.windows()) == 0 {
		t.Error("no recovery sweep ran at start")
	}
}

// The negative-RecoverAfter case that used to live here moved into
// TestWorkerRecoveryWindowNeverReclaimsLiveClaims (worker_recovery_test.go), which
// covers zero and negative in one table. Its comment here asserted that "the zero
// value deliberately means the opposite (reclaim everything)" — production proved
// that reading wrong, and a test comment stating the bug as the contract is worse
// than no comment.

// TestWorkerCleansUpEvenWhenAckFails pins the published-but-unacked case. The image
// IS in ACR at this point, so the only remaining question is disk: skipping Cleanup
// because Ack failed would leak the OCI layout on every occurrence, and the job is
// re-pushable (a duplicate digest push is a no-op) so nothing is lost by acking late.
func TestWorkerCleansUpEvenWhenAckFails(t *testing.T) {
	q := newFaultQueue()
	q.ackErr = errors.New("valkey: HDEL failed")
	pusher := &fakePusher{}
	fin := &fakeFinalizer{}
	var mu sync.Mutex
	var cleaned int
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: fin,
		Cleanup: func(context.Context, Job) error {
			mu.Lock()
			defer mu.Unlock()
			cleaned++
			return nil
		},
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return cleaned >= 1
	})
	if !fin.ok("p1") {
		t.Error("a published image was not recorded as promoted")
	}
}

// TestWorkerLeavesClaimForRecoveryWhenRequeueFails is the data-loss guard on the
// retry path. If the requeue fails, acking the claim anyway drops an approved image
// on the floor with nothing but a log line. Leaving it claimed costs a recovery
// window and loses nothing.
func TestWorkerLeavesClaimForRecoveryWhenRequeueFails(t *testing.T) {
	q := newFaultQueue()
	q.enqueueErr = errors.New("valkey: RPUSH failed")
	pusher := &fakePusher{err: errors.New("acr 503")}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Cleanup:  func(context.Context, Job) error { return nil },
		// Above the attempts this test allows, so the terminal branch (which DOES ack)
		// is unreachable and any ack could only come from the requeue path.
		MaxAttempts: 200,
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitFor(t, func() bool { _, _, enqueues := q.counts(); return enqueues >= 1 })
	// Give the worker room to do the wrong thing before asserting it did not.
	time.Sleep(20 * time.Millisecond)
	if _, acks, _ := q.counts(); acks != 0 {
		t.Errorf("acks = %d, want 0; the claim was dropped after a failed requeue, losing an approved image", acks)
	}
	// And the claim is genuinely still there for a later sweep to find.
	got, err := q.Queue.Recover(context.Background(), 0)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(got) != 1 || got[0].PushID != "p1" {
		t.Errorf("recoverable claims = %+v, want the unacked job p1", got)
	}
}

// TestWorkerRequeuesEvenWhenAckFails is the opposite ordering choice from the test
// above, and the reason Enqueue comes first: with the job already back on the queue,
// a failed Ack can only cause a duplicate push, which a content-addressed registry
// absorbs. Both branches must be exercised or the ordering is untested.
func TestWorkerRequeuesEvenWhenAckFails(t *testing.T) {
	q := newFaultQueue()
	q.ackErr = errors.New("valkey: HDEL failed")
	pusher := &fakePusher{err: errors.New("acr 503")}
	w := testWorker(&Worker{
		Queue:       q,
		Pushers:     func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder:    &fakeFinalizer{},
		Cleanup:     func(context.Context, Job) error { return nil },
		MaxAttempts: 200,
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// The requeue happened and the worker kept going despite the ack failure.
	waitFor(t, func() bool { return pusher.calls() >= 2 })
	if _, acks, enqueues := q.counts(); acks == 0 || enqueues == 0 {
		t.Errorf("acks = %d, enqueues = %d; want both > 0 (requeue then ack)", acks, enqueues)
	}
}

// TestWorkerRetiresEvenWhenAckFails pins that a failed Ack on the terminal path
// still records the abandonment and releases the disk. The job will be recovered and
// retried, which is wasted work — but an unexplained missing image is worse.
func TestWorkerRetiresEvenWhenAckFails(t *testing.T) {
	q := newFaultQueue()
	q.ackErr = errors.New("valkey: HDEL failed")
	pusher := &fakePusher{err: errors.New("acr 401 unauthorized")}
	fin := &fakeFinalizer{}
	var mu sync.Mutex
	var cleaned int
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: fin,
		Cleanup: func(context.Context, Job) error {
			mu.Lock()
			defer mu.Unlock()
			cleaned++
			return nil
		},
		MaxAttempts: 1,
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitFor(t, func() bool { _, ok := fin.failed("p1"); return ok })
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return cleaned >= 1
	})
}

// TestWorkerToleratesCleanupFailureAndNoRecorder pins the two optional
// collaborators. A Cleanup error must not abort the loop (the disk leak is already
// logged; stalling promotion on top of it helps nobody), and a nil Recorder is the
// documented hermetic configuration used by app.Build — a panic there would take
// down the whole process at startup.
func TestWorkerToleratesCleanupFailureAndNoRecorder(t *testing.T) {
	q := newFaultQueue()
	pusher := &fakePusher{}
	var mu sync.Mutex
	var cleanups int
	w := testWorker(&Worker{
		Queue:   q,
		Pushers: func(string) (acr.Pusher, error) { return pusher, nil },
		// Recorder deliberately nil.
		Cleanup: func(context.Context, Job) error {
			mu.Lock()
			defer mu.Unlock()
			cleanups++
			return errors.New("rmdir: device or resource busy")
		},
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1"})
	q.seed(t, Job{PushID: "p2", Target: "acr.io/app:v2"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// The second job is the assertion: a Cleanup error on the first must not stop the
	// worker from draining the rest of the queue.
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return cleanups == 2
	})
	if got := pusher.calls(); got != 2 {
		t.Errorf("pushes = %d, want 2", got)
	}
}

// TestQueuePromoterReportsBacklog pins the load-shedding input. The handler admits
// or rejects work based on this number, and a Promoter that under-reports its
// backlog lets pending OCI layouts fill the scratch volume.
func TestQueuePromoterReportsBacklog(t *testing.T) {
	q := NewMemoryQueue()
	p := QueuePromoter{Queue: q}
	ctx := context.Background()

	if n, err := p.Pending(ctx); err != nil || n != 0 {
		t.Fatalf("Pending on an empty queue = (%d, %v), want (0, nil)", n, err)
	}
	for _, id := range []string{"p1", "p2", "p3"} {
		if err := p.Promote(ctx, Job{PushID: id}); err != nil {
			t.Fatalf("Promote %s: %v", id, err)
		}
	}
	if n, err := p.Pending(ctx); err != nil || n != 3 {
		t.Errorf("Pending = (%d, %v), want (3, nil)", n, err)
	}
	// Claimed work is draining, not waiting: counting it would make the gate shed load
	// it could have accepted.
	if _, ok, err := q.Claim(ctx); err != nil || !ok {
		t.Fatalf("Claim: ok=%v err=%v", ok, err)
	}
	if n, err := p.Pending(ctx); err != nil || n != 2 {
		t.Errorf("Pending after a claim = (%d, %v), want (2, nil)", n, err)
	}
}

// waitFor2 is waitFor with an explicit deadline, for the one case that must outlast
// the claim backoff.
func waitFor2(t *testing.T, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within %v", within)
}
