package dashboard

import (
	"sync"

	"github.com/merlin-gate/merlin/internal/audit"
)

// Broadcaster fans recorded decisions out to SSE subscribers. Publish is
// non-blocking: a subscriber whose buffer is full drops the message rather than
// blocking the publisher (which is the gate's audit path). It must never block.
type Broadcaster struct {
	mu     sync.RWMutex
	subs   map[int]chan audit.DecisionSummary
	nextID int
	buffer int
}

// NewBroadcaster creates a broadcaster; buffer is the per-subscriber channel size.
func NewBroadcaster(buffer int) *Broadcaster {
	if buffer < 1 {
		buffer = 16
	}
	return &Broadcaster{subs: make(map[int]chan audit.DecisionSummary), buffer: buffer}
}

// Subscribe returns a receive channel and an unsubscribe func (idempotent).
func (b *Broadcaster) Subscribe() (<-chan audit.DecisionSummary, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextID
	b.nextID++
	ch := make(chan audit.DecisionSummary, b.buffer)
	b.subs[id] = ch
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if c, ok := b.subs[id]; ok {
				delete(b.subs, id)
				close(c)
			}
		})
	}
	return ch, cancel
}

// Publish delivers d to all subscribers without blocking. Full subscribers drop d.
func (b *Broadcaster) Publish(d audit.DecisionSummary) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- d:
		default: // slow subscriber: drop rather than block the gate's audit path
		}
	}
}

// SubscriberCount returns the current number of subscribers (for tests/metrics).
func (b *Broadcaster) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
