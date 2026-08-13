package promote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
)

// fakePusher counts pushes and can be made to fail. It satisfies acr.Pusher; only
// Push is exercised, but the other two methods must exist to satisfy the interface.
type fakePusher struct {
	mu    sync.Mutex
	n     int
	paths []string // OCI layout path of each push, in order
	err   error
	block chan struct{} // when non-nil, Push waits on it before returning
	// blockFrom, when > 0, restricts blocking to the blockFrom'th call onward, so a
	// test can let the first few pushes fail fast and then park the worker mid-push
	// at a known attempt. Without it the only choices are "never block" and "block
	// immediately", neither of which can hold the worker at a chosen attempt.
	blockFrom int
}

func (p *fakePusher) Push(ctx context.Context, ociPath, target string) error {
	p.mu.Lock()
	p.n++
	p.paths = append(p.paths, ociPath)
	block, err := p.block, p.err
	if p.blockFrom > 0 && p.n < p.blockFrom {
		block = nil
	}
	p.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (p *fakePusher) PushManifest(context.Context, []byte, string, string) error { return nil }
func (p *fakePusher) PushBlob(context.Context, []byte, string, string) error     { return nil }

func (p *fakePusher) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

func (p *fakePusher) pushedPaths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.paths...)
}

// fakeFinalizer records what the worker reported about each promotion.
type fakeFinalizer struct {
	mu   sync.Mutex
	seen []finalizeCall
}

type finalizeCall struct {
	job    Job
	ok     bool
	detail string
}

func (f *fakeFinalizer) FinalizePromotion(_ context.Context, j Job, ok bool, detail string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, finalizeCall{job: j, ok: ok, detail: detail})
}

func (f *fakeFinalizer) calls() []finalizeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]finalizeCall(nil), f.seen...)
}

// ok reports whether a SUCCESSFUL promotion was finalized for pushID.
func (f *fakeFinalizer) ok(pushID string) bool {
	for _, c := range f.calls() {
		if c.job.PushID == pushID && c.ok {
			return true
		}
	}
	return false
}

// failed reports whether a TERMINAL failure was finalized for pushID.
func (f *fakeFinalizer) failed(pushID string) (string, bool) {
	for _, c := range f.calls() {
		if c.job.PushID == pushID && !c.ok {
			return c.detail, true
		}
	}
	return "", false
}

// waitFor polls cond until it holds or the deadline passes. Polling (rather than a
// channel handshake) keeps the tests independent of the worker's internal
// sequencing: they assert observable effects, not the order of its steps.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within 3s")
}

// testWorker builds a worker with the fast poll interval the tests need. The
// production default (200ms) would make every test wait a poll cycle.
func testWorker(w *Worker) *Worker {
	w.PollInterval = time.Millisecond
	return w
}

func TestWorkerPushesAndCleansUp(t *testing.T) {
	q := NewMemoryQueue()
	pusher := &fakePusher{}
	var mu sync.Mutex
	var cleaned bool
	fin := &fakeFinalizer{}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: fin,
		Cleanup: func(context.Context, Job) error {
			mu.Lock()
			defer mu.Unlock()
			cleaned = true
			return nil
		},
	})
	if err := q.Enqueue(context.Background(), Job{PushID: "p1", Target: "acr.io/app:v1", OCIPath: "/tmp/oci"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return pusher.calls() == 1 && cleaned
	})

	if !fin.ok("p1") {
		t.Error("promotion success was not recorded on the decision")
	}
	// A successful promotion must be acked, or Recover would resurrect it and
	// re-push an image that is already published.
	waitFor(t, func() bool {
		got, err := q.Recover(context.Background(), 0)
		return err == nil && len(got) == 0
	})
}

// TestWorkerKeepsScratchForRetry pins the ordering constraint that makes retry
// possible at all: deleting the OCI layout after a failed push leaves the retry
// nothing to push, so the job is doomed for the rest of its attempt budget.
func TestWorkerKeepsScratchForRetry(t *testing.T) {
	q := NewMemoryQueue()
	// Fail the first three pushes fast, then park inside the fourth. The parked call
	// is what makes this deterministic: at assertion time the worker is provably
	// mid-push at attempt 4, so it cannot have reached the terminal branch, and any
	// Cleanup must have come from a RETRYABLE failure. Bounding attempts alone does
	// not achieve that — retries here have no backoff, so the worker burns the whole
	// budget in microseconds and legitimately retires the job (calling Cleanup)
	// before a polling assertion ever runs. That made this test pass only under
	// -race, which slowed it enough to hide the real ordering.
	pusher := &fakePusher{err: errors.New("acr 503"), block: make(chan struct{}), blockFrom: 4}
	var mu sync.Mutex
	var cleaned bool
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Cleanup: func(context.Context, Job) error {
			mu.Lock()
			defer mu.Unlock()
			cleaned = true
			return nil
		},
		// A budget far above the attempts this test allows to complete. Combined with
		// the parked fourth push above, the terminal branch is unreachable, so
		// `cleaned` can only be set by a retryable failure.
		MaxAttempts: 200,
	})
	if err := q.Enqueue(context.Background(), Job{PushID: "p1", Target: "acr.io/app:v1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	// Three retryable failures observed, and the worker now blocked inside the fourth
	// push. Assert BEFORE cancelling: once the worker is unblocked it may legitimately
	// clean up, and asserting after cancel would race that shutdown.
	waitFor(t, func() bool { return pusher.calls() >= 4 })

	mu.Lock()
	defer mu.Unlock()
	if cleaned {
		t.Error("scratch dir was deleted after a retryable failure; the retry cannot succeed")
	}
}

// TestWorkerResolvesPusherByTenantNotRepo is the guard against the worst failure
// this package can produce: publishing one tenant's image into another tenant's
// registry. Both fixtures host the same repo NAME, which is legal under the
// multi-ACR config and indistinguishable if the worker keys on Repo.
func TestWorkerResolvesPusherByTenantNotRepo(t *testing.T) {
	devops := &fakePusher{}
	prod := &fakePusher{}
	byPrefix := map[string]acr.Pusher{"c3devops": devops, "c3prod": prod}

	q := NewMemoryQueue()
	w := testWorker(&Worker{
		Queue: q,
		Pushers: func(prefix string) (acr.Pusher, error) {
			p, ok := byPrefix[prefix]
			if !ok {
				return nil, errors.New("unknown tenant prefix " + prefix)
			}
			return p, nil
		},
		Recorder: &fakeFinalizer{},
		Cleanup:  func(context.Context, Job) error { return nil },
	})
	if err := q.Enqueue(context.Background(), Job{
		PushID: "p1", Tenant: "c3prod", Repo: "c3aiops",
		Target: "c3prod.azurecr.io/c3aiops:v1",
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool { return prod.calls() >= 1 })

	if devops.calls() != 0 {
		t.Fatalf("image published to the wrong tenant's registry: devops got %d pushes", devops.calls())
	}
}

// TestWorkerRetiresJobAfterAttemptBudget pins the other end of the retry policy.
// Without a budget a permanently failing push (bad credentials, deleted repo)
// re-queues forever, holding its scratch dir and starving real work.
func TestWorkerRetiresJobAfterAttemptBudget(t *testing.T) {
	q := NewMemoryQueue()
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
		MaxAttempts: 3,
	})
	if err := q.Enqueue(context.Background(), Job{PushID: "p1", Target: "acr.io/app:v1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	detail := ""
	waitFor(t, func() bool {
		d, ok := fin.failed("p1")
		detail = d
		return ok
	})
	if detail == "" {
		t.Error("terminal failure recorded with no cause; the audit row is unexplainable")
	}
	// Exactly the budget, not one more: an off-by-one here is a wasted ACR push per
	// job under a registry outage.
	if got := pusher.calls(); got != 3 {
		t.Errorf("push attempts = %d, want 3 (MaxAttempts)", got)
	}
	// The job must be gone: neither claimable nor recoverable. A retired job that
	// stays in the queue is the forever-loop this budget exists to prevent.
	waitFor(t, func() bool {
		_, ok, err := q.Claim(context.Background())
		if err != nil || ok {
			return false
		}
		got, rerr := q.Recover(context.Background(), 0)
		return rerr == nil && len(got) == 0
	})
	// Scratch IS released on the terminal attempt — no retry will follow, so holding
	// the OCI layout would leak it permanently.
	mu.Lock()
	defer mu.Unlock()
	if cleaned == 0 {
		t.Error("scratch dir was never released for a permanently failed job (disk leak)")
	}
}

// TestWorkerRetiresJobWhenTenantIsUnresolvable pins that an unresolvable tenant is
// NOT retried. Retrying it burns the attempt budget on an error no retry can fix,
// and (worse) an unresolvable prefix must never fall back to some other pusher.
func TestWorkerRetiresJobWhenTenantIsUnresolvable(t *testing.T) {
	q := NewMemoryQueue()
	fin := &fakeFinalizer{}
	var resolves int
	var mu sync.Mutex
	w := testWorker(&Worker{
		Queue: q,
		Pushers: func(string) (acr.Pusher, error) {
			mu.Lock()
			resolves++
			mu.Unlock()
			return nil, errors.New("no registry configured for tenant")
		},
		Recorder:    fin,
		Cleanup:     func(context.Context, Job) error { return nil },
		MaxAttempts: 3,
	})
	if err := q.Enqueue(context.Background(), Job{PushID: "p1", Tenant: "ghost"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	waitFor(t, func() bool { _, ok := fin.failed("p1"); return ok })
	mu.Lock()
	defer mu.Unlock()
	if resolves != 1 {
		t.Errorf("pusher resolution attempts = %d, want 1 (a missing tenant is not retryable)", resolves)
	}
}

// TestWorkerRecoversAbandonedClaimsOnStart pins the OOMKill recovery path from the
// worker's side: a claim left by a dead predecessor must be promoted, not stranded.
//
// The claim is aged with the queue's clock rather than by widening the worker's
// window to zero. That distinction is the whole point after the reclaim-everything
// outage: this test and TestWorkerDoesNotStealAFreshSiblingClaim differ ONLY in how
// old the claim is, so they cannot both pass unless the window is respected. Setting
// RecoverAfter: 0 here made this test pass for the wrong reason and left the real
// production configuration untested.
func TestWorkerRecoversAbandonedClaimsOnStart(t *testing.T) {
	q := NewMemoryQueue().(*memoryQueue)
	ctx := context.Background()
	if err := q.Enqueue(ctx, Job{PushID: "orphan", Target: "acr.io/app:v1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// A predecessor claimed it well outside the recovery window and died without
	// acking. Written before Run starts, so the worker goroutine never races it.
	q.now = func() time.Time { return time.Now().Add(-defaultRecoverAfter - time.Minute) }
	if _, ok, _ := q.Claim(ctx); !ok {
		t.Fatal("setup: claim failed")
	}
	q.now = time.Now

	pusher := &fakePusher{}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Cleanup:  func(context.Context, Job) error { return nil },
		// RecoverAfter unset: the production wiring, and the default window is what
		// makes the aged claim recoverable.
	})
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(runCtx)

	waitFor(t, func() bool { return pusher.calls() >= 1 })
}

// TestWorkerRebuildsLayoutAssembledOnAnotherPod is the cross-replica guard.
//
// scratch is an emptyDir — per POD — while the promotion queue is a single shared
// Valkey list and the chart runs replicaCount: 2. Claim is a bare LPOP with no
// owner scoping, so roughly half of all jobs are claimed by the pod that did NOT
// assemble the image. That pod finds no OCI layout, burns the whole attempt budget
// against a path that was never on its filesystem, and retires the job — while the
// client is already holding its 201. "Approved but silently never published."
func TestWorkerRebuildsLayoutAssembledOnAnotherPod(t *testing.T) {
	q := NewMemoryQueue()
	pusher := &fakePusher{}

	// What THIS pod can rebuild, from blobs still present in the shared staging
	// store (Cleanup has not run, so the ref-counts are still held).
	localScratch := t.TempDir()
	localOCI := filepath.Join(localScratch, "oci")
	if err := os.MkdirAll(localOCI, 0o755); err != nil {
		t.Fatalf("setup local layout: %v", err)
	}

	var mu sync.Mutex
	var localizeCalls int
	var cleanedWith string
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Localize: func(context.Context, Job) (string, string, error) {
			mu.Lock()
			localizeCalls++
			mu.Unlock()
			return localOCI, localScratch, nil
		},
		Cleanup: func(_ context.Context, j Job) error {
			mu.Lock()
			defer mu.Unlock()
			cleanedWith = j.ScratchDir
			return nil
		},
	})

	// The ORIGIN pod's paths. Neither exists here; that is the whole scenario.
	if err := q.Enqueue(context.Background(), Job{
		PushID: "p1", Target: "acr.io/app:v1",
		OCIPath:    filepath.Join(t.TempDir(), "gone", "oci"),
		ScratchDir: filepath.Join(t.TempDir(), "gone"),
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return pusher.calls() == 1 && cleanedWith != ""
	})

	if got := pusher.pushedPaths(); got[0] != localOCI {
		t.Errorf("pushed OCI path = %q, want the rebuilt local layout %q", got[0], localOCI)
	}
	// Cleanup must target what THIS pod created. Removing the origin pod's path is a
	// no-op on this filesystem and leaks the layout that was just rebuilt.
	mu.Lock()
	defer mu.Unlock()
	if cleanedWith != localScratch {
		t.Errorf("cleaned scratch dir = %q, want the rebuilt %q", cleanedWith, localScratch)
	}
	if localizeCalls != 1 {
		t.Errorf("localize calls = %d, want 1", localizeCalls)
	}
}

// TestWorkerDoesNotRebuildLayoutItAlreadyHas keeps the common case cheap: when the
// claiming pod IS the pod that assembled the image, re-fetching every blob from
// Azure Blob and re-extracting the layers would double the cost of every promotion.
func TestWorkerDoesNotRebuildLayoutItAlreadyHas(t *testing.T) {
	q := NewMemoryQueue()
	pusher := &fakePusher{}
	scratch := t.TempDir()
	ociPath := filepath.Join(scratch, "oci")
	if err := os.MkdirAll(ociPath, 0o755); err != nil {
		t.Fatalf("setup local layout: %v", err)
	}

	var mu sync.Mutex
	var localizeCalls int
	var done bool
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Localize: func(context.Context, Job) (string, string, error) {
			mu.Lock()
			localizeCalls++
			mu.Unlock()
			return "", "", errors.New("must not be called")
		},
		Cleanup: func(context.Context, Job) error {
			mu.Lock()
			defer mu.Unlock()
			done = true
			return nil
		},
	})
	if err := q.Enqueue(context.Background(), Job{
		PushID: "p1", Target: "acr.io/app:v1", OCIPath: ociPath, ScratchDir: scratch,
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return done
	})

	mu.Lock()
	defer mu.Unlock()
	if localizeCalls != 0 {
		t.Errorf("localize calls = %d, want 0; the layout was already on this pod", localizeCalls)
	}
}

// TestWorkerRetiresWhenLayoutCannotBeRebuilt pins that an unrebuildable layout is
// RECORDED, not silently dropped. The staged blobs expire or a sibling's Cleanup
// released them, so there is nothing left to assemble — and the client already has a
// 201 saying the image passed. The contradicting audit row is the only way an
// operator ever learns the image is not in ACR.
func TestWorkerRetiresWhenLayoutCannotBeRebuilt(t *testing.T) {
	q := NewMemoryQueue()
	pusher := &fakePusher{}
	fin := &fakeFinalizer{}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: fin,
		Localize: func(context.Context, Job) (string, string, error) {
			return "", "", errors.New("staged blob 404: already released")
		},
		Cleanup:     func(context.Context, Job) error { return nil },
		MaxAttempts: 2,
	})
	if err := q.Enqueue(context.Background(), Job{
		PushID: "p1", Target: "acr.io/app:v1", OCIPath: filepath.Join(t.TempDir(), "gone", "oci"),
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	detail := ""
	waitFor(t, func() bool {
		d, ok := fin.failed("p1")
		detail = d
		return ok
	})
	if detail == "" {
		t.Error("terminal failure recorded with no cause; the audit row is unexplainable")
	}
	// Never push a layout we know is absent: go-containerregistry would fail on an
	// empty/missing directory, and a "success" there would be far worse.
	if n := pusher.calls(); n != 0 {
		t.Errorf("pushes = %d, want 0; a missing layout must not reach ACR", n)
	}
}

// TestWorkerDoesNotStealLiveClaims is the multi-replica guard. The chart runs
// replicaCount: 2, so a starting worker that reclaims every outstanding claim would
// promote an image its sibling is pushing right now — a duplicate push, and for a
// tag target a tag that moves backward.
func TestWorkerDoesNotStealLiveClaims(t *testing.T) {
	q := NewMemoryQueue()
	ctx := context.Background()
	if err := q.Enqueue(ctx, Job{PushID: "inflight", Target: "acr.io/app:v1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, ok, _ := q.Claim(ctx); !ok { // the sibling replica holds it
		t.Fatal("setup: claim failed")
	}

	pusher := &fakePusher{}
	w := testWorker(&Worker{
		Queue:        q,
		Pushers:      func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder:     &fakeFinalizer{},
		Cleanup:      func(context.Context, Job) error { return nil },
		RecoverAfter: time.Hour,
	})
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(runCtx)

	time.Sleep(50 * time.Millisecond) // long enough for several poll cycles
	if n := pusher.calls(); n != 0 {
		t.Errorf("pushes = %d, want 0; the worker stole a claim its sibling still holds", n)
	}
}
