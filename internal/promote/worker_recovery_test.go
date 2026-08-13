package promote

import (
	"context"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
)

// TestWorkerRecoveryWindowNeverReclaimsLiveClaims is the regression test for the
// outage of 2026-08-13: a promotion queue in which every in-flight claim was stolen
// by a sibling replica within seconds.
//
// Recover's contract is "requeue claims OLDER than this window". Recover(ctx, 0)
// therefore sets the cutoff at `now`, so a claim made a millisecond ago is already
// "older" and gets requeued — reclaim-everything. Worker.RecoverAfter's own doc
// comment says that must never be the default, because the chart runs several
// replicas and a stolen claim means two pods pushing the same image; but recover()
// only guarded `< 0`, and nothing in app.go ever set the field. Production ran with
// zero.
//
// What that cost, from the live cluster: ONE approved image (push
// 49a1e2b3…, c3.ai/opensearch-fips) was worked by SIX pods at once. The first
// duplicate to finish ran Cleanup, which released the push's staged-blob
// ref-counts and deleted the bytes — so every other duplicate then failed
// `get blob sha256:a908800029e8…: 404 BlobNotFound` and each wrote an audit row
// contradicting a push that had in fact succeeded. 160 such rows in 24h, the
// single largest failure class on the gate.
//
// The table covers zero and negative together on purpose: both are nonsense
// windows, and the trap was that they failed in opposite directions (zero reclaimed
// everything, negative reclaimed nothing) while looking equally harmless.
func TestWorkerRecoveryWindowNeverReclaimsLiveClaims(t *testing.T) {
	tests := []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{"unset", 0, defaultRecoverAfter},
		{"negative", -time.Minute, defaultRecoverAfter},
		{"explicit", 90 * time.Second, 90 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := newFaultQueue()
			w := testWorker(&Worker{
				Queue:        q,
				Pushers:      func(string) (acr.Pusher, error) { return &fakePusher{}, nil },
				Recorder:     &fakeFinalizer{},
				RecoverAfter: tc.set,
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go w.Run(ctx)

			waitFor(t, func() bool { return len(q.windows()) > 0 })
			if got := q.windows()[0]; got != tc.want {
				t.Errorf("recover window = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWorkerDoesNotStealAFreshSiblingClaim is the same guard stated as behaviour
// rather than as a parameter: with the worker left at its production
// configuration (RecoverAfter unset), a claim another replica made moments ago must
// still be claimed when the sweep finishes. The window test above pins the number;
// this one pins that the number is actually load-bearing, so a future refactor
// cannot satisfy the assertion while still requeueing the job.
func TestWorkerDoesNotStealAFreshSiblingClaim(t *testing.T) {
	q := NewMemoryQueue()
	ctx := context.Background()
	if err := q.Enqueue(ctx, Job{PushID: "sibling", Target: "acr.io/app:v1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// A live sibling replica holds the claim and is mid-push.
	if _, ok, _ := q.Claim(ctx); !ok {
		t.Fatal("setup: claim failed")
	}

	pusher := &fakePusher{}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Cleanup:  func(context.Context, Job) error { return nil },
		// RecoverAfter deliberately unset: this is the production wiring.
	})
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(runCtx)

	// The sweep runs immediately at start, so by the time a few poll cycles have
	// passed either the job was stolen or it was not.
	time.Sleep(50 * time.Millisecond)
	if got := pusher.calls(); got != 0 {
		t.Errorf("pushes = %d, want 0: this worker stole a claim its sibling is still pushing", got)
	}
	if n, _ := q.Depth(ctx); n != 0 {
		t.Errorf("pending depth = %d, want 0: the live claim was requeued", n)
	}
}
