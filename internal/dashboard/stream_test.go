package dashboard

import (
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
)

func TestBroadcasterDelivers(t *testing.T) {
	b := NewBroadcaster(4)
	ch, cancel := b.Subscribe()
	defer cancel()
	b.Publish(audit.DecisionSummary{Repo: "a/b", Tag: "v1"})
	select {
	case d := <-ch:
		if d.Repo != "a/b" {
			t.Errorf("got repo %q", d.Repo)
		}
	case <-time.After(time.Second):
		t.Fatal("no delivery")
	}
}

func TestBroadcasterUnsubscribe(t *testing.T) {
	b := NewBroadcaster(4)
	_, cancel := b.Subscribe()
	if b.SubscriberCount() != 1 {
		t.Fatalf("count=%d want 1", b.SubscriberCount())
	}
	cancel()
	if b.SubscriberCount() != 0 {
		t.Fatalf("count=%d want 0 after cancel", b.SubscriberCount())
	}
}

func TestBroadcasterDropsSlowSubscriber(t *testing.T) {
	b := NewBroadcaster(1) // tiny buffer
	ch, cancel := b.Subscribe()
	defer cancel()
	// Never drain ch; publishing more than buffer must not block (non-blocking send).
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			b.Publish(audit.DecisionSummary{Repo: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
		_ = ch // publishing completed without blocking on the full subscriber
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}
}
