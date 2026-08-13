package promote

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/merlin-gate/merlin/internal/acr"
)

// terminalErr is a stand-in for staging's *BlobMissingError. The fake is the point:
// promote must classify by BEHAVIOUR (does the error say it is terminal?) and must
// not import internal/staging to do it — the worker also runs against blob stores
// that package knows nothing about, and an import would make the queue depend on the
// staging backend it exists to decouple from.
type terminalErr struct{ msg string }

func (e terminalErr) Error() string  { return e.msg }
func (e terminalErr) Terminal() bool { return true }

// notTerminalErr implements the same method and answers false. Without this case a
// test suite passes just as happily on `if _, ok := cause.(interface{ Terminal() bool
// }); ok` — an assertion that ignores the answer and retires on network blips.
type notTerminalErr struct{ msg string }

func (e notTerminalErr) Error() string  { return e.msg }
func (e notTerminalErr) Terminal() bool { return false }

// TestWorkerDoesNotRetryATerminalFailure is the RED test for the second half of the
// BlobNotFound outage: a promotion whose input is GONE was retried three times.
//
// Each retry re-read the same absent blob key, failed identically, and wrote its own
// contradicting audit row — so one missing blob produced three "abandoned after N
// attempts" records plus two useless requeues, and the audit report (which takes the
// LAST row for a push_id) reported failure for an image already in ACR. A 404 on a
// deleted blob cannot heal: there is no upload in flight to wait for.
//
// The assertion is on the ATTEMPT COUNT, not just on the outcome, because retiring
// after three attempts and retiring after one both end in FinalizePromotion(false).
func TestWorkerDoesNotRetryATerminalFailure(t *testing.T) {
	q := newFaultQueue()
	fin := &fakeFinalizer{}
	var localizeCalls atomic.Int64
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return &fakePusher{}, nil },
		Recorder: fin,
		Cleanup:  func(context.Context, Job) error { return nil },
		Localize: func(context.Context, Job) (string, string, error) {
			localizeCalls.Add(1)
			return "", "", fmt.Errorf("re-assemble acr.io/app:v1: %w",
				terminalErr{msg: `get blob sha256:a908800029e8: blob "blob/sha256:a908800029e8" not found in staging store`})
		},
	})
	// A path that does not exist on this pod, so localize actually runs.
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1", OCIPath: "/nonexistent/oci"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	detail, ok := waitForFailure(t, fin, "p1")
	if !ok {
		t.Fatal("job was never finalized")
	}
	if got := localizeCalls.Load(); got != 1 {
		t.Errorf("localize attempts = %d, want 1 (a missing blob cannot appear on retry)", got)
	}
	if _, _, enqueues := q.counts(); enqueues != 0 {
		t.Errorf("requeues = %d, want 0 (a terminal failure must not go back on the queue)", enqueues)
	}
	// The record must name the real cause. "abandoned after 3 attempts: acr push"
	// sent three people looking at ACR credentials for a staging-store problem.
	if !strings.Contains(detail, "not found in staging store") {
		t.Errorf("audit detail = %q, want it to name the missing blob", detail)
	}
}

// TestWorkerStillRetriesANonTerminalFailure is the guard on the other side. The
// worker's whole retry budget exists for weather — a briefly unreachable blob store,
// a mid-upload blob — and classifying those as terminal would abandon images that
// one retry would have published, which is the exact failure this package exists to
// prevent. Terminal() answering false must be honoured, not merely present.
func TestWorkerStillRetriesANonTerminalFailure(t *testing.T) {
	q := newFaultQueue()
	fin := &fakeFinalizer{}
	var localizeCalls atomic.Int64
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return &fakePusher{}, nil },
		Recorder: fin,
		Cleanup:  func(context.Context, Job) error { return nil },
		Localize: func(context.Context, Job) (string, string, error) {
			localizeCalls.Add(1)
			return "", "", notTerminalErr{msg: "staging store: dial tcp: connection refused"}
		},
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1", OCIPath: "/nonexistent/oci"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	if _, ok := waitForFailure(t, fin, "p1"); !ok {
		t.Fatal("job was never finalized")
	}
	if got := localizeCalls.Load(); got != int64(defaultMaxAttempts) {
		t.Errorf("localize attempts = %d, want %d (weather deserves the full budget)",
			got, defaultMaxAttempts)
	}
}

// TestWorkerTreatsAnUnclassifiedFailureAsRetryable pins the default for the errors
// that carry no Terminal method at all — which is most of them. Retrying something
// unretryable costs two wasted attempts; abandoning something retryable loses an
// approved image, so the ambiguous case must fall on the retry side.
func TestWorkerTreatsAnUnclassifiedFailureAsRetryable(t *testing.T) {
	q := newFaultQueue()
	fin := &fakeFinalizer{}
	var localizeCalls atomic.Int64
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return &fakePusher{}, nil },
		Recorder: fin,
		Cleanup:  func(context.Context, Job) error { return nil },
		Localize: func(context.Context, Job) (string, string, error) {
			localizeCalls.Add(1)
			return "", "", errors.New("something went wrong")
		},
	})
	q.seed(t, Job{PushID: "p1", Target: "acr.io/app:v1", OCIPath: "/nonexistent/oci"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	if _, ok := waitForFailure(t, fin, "p1"); !ok {
		t.Fatal("job was never finalized")
	}
	if got := localizeCalls.Load(); got != int64(defaultMaxAttempts) {
		t.Errorf("localize attempts = %d, want %d", got, defaultMaxAttempts)
	}
}

// waitForFailure blocks until the job has been finalized as failed and returns the
// recorded detail.
func waitForFailure(t *testing.T, fin *fakeFinalizer, pushID string) (string, bool) {
	t.Helper()
	var detail string
	var found bool
	waitFor(t, func() bool {
		detail, found = fin.failed(pushID)
		return found
	})
	return detail, found
}
