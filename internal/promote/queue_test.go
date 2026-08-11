package promote

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// queueImpls lists every Queue implementation that must satisfy the contract in
// this file. valkey_integration_test.go (build tag `integration`) appends the
// Valkey-backed queue, so `go test` stays hermetic while the Lua that makes Claim
// atomic is held to the identical contract whenever a Valkey is reachable.
var queueImpls = []struct {
	name string
	new  func(t *testing.T) Queue
}{
	{"memory", func(t *testing.T) Queue { return NewMemoryQueue() }},
}

func TestEnqueueClaimAckRoundTrip(t *testing.T) {
	for _, impl := range queueImpls {
		t.Run(impl.name, func(t *testing.T) {
			q := impl.new(t)
			ctx := context.Background()
			want := Job{PushID: "abc123", Tenant: "c3devops", Repo: "app", Ref: "v1",
				Target: "acr.io/app:v1", OCIPath: "/tmp/x/oci"}

			if err := q.Enqueue(ctx, want); err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			got, ok, err := q.Claim(ctx)
			if err != nil || !ok {
				t.Fatalf("Claim: ok=%v err=%v", ok, err)
			}
			if got.PushID != want.PushID || got.Target != want.Target {
				t.Errorf("Claim = %+v, want %+v", got, want)
			}
			// Tenant is the only thing that tells the worker WHICH ACR to publish to.
			// If it does not survive the round trip the worker cannot resolve a pusher
			// (or, worse, guesses one) and the image lands in the wrong registry.
			if got.Tenant != want.Tenant {
				t.Errorf("Claim tenant = %q, want %q", got.Tenant, want.Tenant)
			}
			// A claimed job must NOT be handed to a second worker.
			if _, ok, _ := q.Claim(ctx); ok {
				t.Error("claimed job was handed out twice")
			}
			if err := q.Ack(ctx, want.PushID); err != nil {
				t.Fatalf("Ack: %v", err)
			}
		})
	}
}

// TestRecoverRequeuesAbandonedClaim is the test that justifies the whole queue: it
// encodes the OOMKill case. A worker that dies mid-promotion leaves a claim with no
// one to Ack it; without Recover the image is never published and the audit row
// never updates.
func TestRecoverRequeuesAbandonedClaim(t *testing.T) {
	for _, impl := range queueImpls {
		t.Run(impl.name, func(t *testing.T) {
			q := impl.new(t)
			ctx := context.Background()
			if err := q.Enqueue(ctx, Job{PushID: "abandoned", Target: "acr.io/app:v1"}); err != nil {
				t.Fatalf("Enqueue: %v", err)
			}

			// Worker claims, then the process dies without Ack.
			if _, ok, _ := q.Claim(ctx); !ok {
				t.Fatal("setup: claim failed")
			}
			if _, ok, _ := q.Claim(ctx); ok {
				t.Fatal("setup: job should be invisible while claimed")
			}

			got, err := q.Recover(ctx, 0) // 0 == reclaim everything currently claimed
			if err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if len(got) != 1 || got[0].PushID != "abandoned" {
				t.Fatalf("Recover = %+v, want the abandoned job", got)
			}
			if _, ok, _ := q.Claim(ctx); !ok {
				t.Error("recovered job is not claimable again")
			}
		})
	}
}

// TestRecoverLeavesFreshClaimsAlone pins the other half of Recover: a claim held by
// a LIVE worker mid-push must not be re-queued, or a long ACR push gets promoted
// twice concurrently by two workers.
func TestRecoverLeavesFreshClaimsAlone(t *testing.T) {
	for _, impl := range queueImpls {
		t.Run(impl.name, func(t *testing.T) {
			q := impl.new(t)
			ctx := context.Background()
			if err := q.Enqueue(ctx, Job{PushID: "inflight", Target: "acr.io/app:v1"}); err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			if _, ok, _ := q.Claim(ctx); !ok {
				t.Fatal("setup: claim failed")
			}

			got, err := q.Recover(ctx, time.Hour)
			if err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("Recover = %+v, want none (claim is only seconds old)", got)
			}
			if _, ok, _ := q.Claim(ctx); ok {
				t.Error("a fresh claim was handed to a second worker")
			}
		})
	}
}

// TestAckedJobIsNotRecovered pins that Ack retires a claim completely. If Ack left
// state behind, Recover would resurrect an already-published image forever.
func TestAckedJobIsNotRecovered(t *testing.T) {
	for _, impl := range queueImpls {
		t.Run(impl.name, func(t *testing.T) {
			q := impl.new(t)
			ctx := context.Background()
			if err := q.Enqueue(ctx, Job{PushID: "done", Target: "acr.io/app:v1"}); err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			if _, ok, _ := q.Claim(ctx); !ok {
				t.Fatal("setup: claim failed")
			}
			if err := q.Ack(ctx, "done"); err != nil {
				t.Fatalf("Ack: %v", err)
			}

			got, err := q.Recover(ctx, 0)
			if err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("Recover = %+v, want none; an acked job was resurrected", got)
			}
			if _, ok, _ := q.Claim(ctx); ok {
				t.Error("an acked job is still claimable")
			}
		})
	}
}

func TestClaimOnEmptyQueueReportsEmpty(t *testing.T) {
	for _, impl := range queueImpls {
		t.Run(impl.name, func(t *testing.T) {
			_, ok, err := impl.new(t).Claim(context.Background())
			if err != nil {
				t.Fatalf("Claim on empty queue: %v", err)
			}
			if ok {
				t.Error("Claim on empty queue reported a job")
			}
		})
	}
}

// TestClaimIsFIFO pins ordering: a burst's first push should be promoted first, so
// the tail of a burst is the only thing that waits.
func TestClaimIsFIFO(t *testing.T) {
	for _, impl := range queueImpls {
		t.Run(impl.name, func(t *testing.T) {
			q := impl.new(t)
			ctx := context.Background()
			for i := 0; i < 3; i++ {
				if err := q.Enqueue(ctx, Job{PushID: fmt.Sprintf("p%d", i)}); err != nil {
					t.Fatalf("Enqueue: %v", err)
				}
			}
			for i := 0; i < 3; i++ {
				got, ok, err := q.Claim(ctx)
				if err != nil || !ok {
					t.Fatalf("Claim %d: ok=%v err=%v", i, ok, err)
				}
				if want := fmt.Sprintf("p%d", i); got.PushID != want {
					t.Errorf("Claim %d = %q, want %q", i, got.PushID, want)
				}
			}
		})
	}
}

// TestConcurrentClaimsHandEachJobOutOnce is the race-detector test for the
// invariant that matters most under a burst: two workers must never promote the
// same image at the same time.
func TestConcurrentClaimsHandEachJobOutOnce(t *testing.T) {
	for _, impl := range queueImpls {
		t.Run(impl.name, func(t *testing.T) {
			q := impl.new(t)
			ctx := context.Background()
			const total = 32
			for i := 0; i < total; i++ {
				if err := q.Enqueue(ctx, Job{PushID: fmt.Sprintf("p%d", i)}); err != nil {
					t.Fatalf("Enqueue: %v", err)
				}
			}

			var mu sync.Mutex
			seen := map[string]int{}
			var wg sync.WaitGroup
			for w := 0; w < 8; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						j, ok, err := q.Claim(ctx)
						if err != nil || !ok {
							return
						}
						mu.Lock()
						seen[j.PushID]++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()

			if len(seen) != total {
				t.Errorf("distinct jobs claimed = %d, want %d", len(seen), total)
			}
			for id, n := range seen {
				if n != 1 {
					t.Errorf("job %s claimed %d times, want 1", id, n)
				}
			}
		})
	}
}
