package promote

import (
	"context"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/merlin-gate/merlin/internal/acr"
)

// spyPromoteMetrics records both promotion observations. It implements
// ObserveACRPush, which the Worker reaches through an optional interface
// assertion — the other fakes in this package deliberately do not, which is what
// keeps them compiling.
type spyPromoteMetrics struct {
	mu        sync.Mutex
	durations []float64
	pushes    []string // "registry|result", in order
}

func (s *spyPromoteMetrics) ObservePromoteDuration(sec float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durations = append(s.durations, sec)
}

func (s *spyPromoteMetrics) ObserveACRPush(registry, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushes = append(s.pushes, registry+"|"+result)
}

func (s *spyPromoteMetrics) observed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.pushes...)
}

// TestWorkerCountsACRPushByRegistryAndResult is the load-bearing half of Change A:
// after promotion became asynchronous the gate's publish step is only an enqueue,
// so THIS is where a real ACR push happens and where the counter must be
// incremented. Without it merlin_acr_push_total measures queue health.
func TestWorkerCountsACRPushByRegistryAndResult(t *testing.T) {
	q := NewMemoryQueue()
	pusher := &fakePusher{}
	sm := &spyPromoteMetrics{}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Metrics:  sm,
	})
	if err := q.Enqueue(context.Background(), Job{PushID: "p1", Target: "c3devops.azurecr.io/app:v1", OCIPath: "/tmp/oci"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool { return len(sm.observed()) == 1 })

	if got, want := sm.observed()[0], "c3devops.azurecr.io|ok"; got != want {
		t.Errorf("ObserveACRPush = %q, want %q", got, want)
	}
}

// TestWorkerCountsEachFailedAttempt pins two things: the failure is attributed to
// its CAUSE (a 401 is an identity problem, not weather), and every attempt is
// counted. Collapsing retries into one observation would hide how long a revoked
// credential persisted — the exact signal PR 2431 lacked.
func TestWorkerCountsEachFailedAttempt(t *testing.T) {
	q := NewMemoryQueue()
	pusher := &fakePusher{err: &transport.Error{StatusCode: 401}}
	sm := &spyPromoteMetrics{}
	w := testWorker(&Worker{
		Queue:       q,
		Pushers:     func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder:    &fakeFinalizer{},
		Metrics:     sm,
		MaxAttempts: 2,
	})
	if err := q.Enqueue(context.Background(), Job{PushID: "p1", Target: "c3devops.azurecr.io/app:v1", OCIPath: "/tmp/oci"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool { return len(sm.observed()) == 2 })

	for i, got := range sm.observed() {
		if want := "c3devops.azurecr.io|auth"; got != want {
			t.Errorf("ObserveACRPush[%d] = %q, want %q", i, got, want)
		}
	}
}

// TestWorkerACRPushObservationIsOptional guards the assertion-based wiring: a
// Metrics implementation that predates ObserveACRPush must not panic the worker,
// because the worker holds the only copy of an approved-but-unpublished image.
func TestWorkerACRPushObservationIsOptional(t *testing.T) {
	q := NewMemoryQueue()
	pusher := &fakePusher{}
	w := testWorker(&Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: &fakeFinalizer{},
		Metrics:  durationOnlyMetrics{},
	})
	if err := q.Enqueue(context.Background(), Job{PushID: "p1", Target: "acr.io/app:v1", OCIPath: "/tmp/oci"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool { return pusher.calls() == 1 })
}

// durationOnlyMetrics is the pre-Change-A metrics shape.
type durationOnlyMetrics struct{}

func (durationOnlyMetrics) ObservePromoteDuration(float64) {}
