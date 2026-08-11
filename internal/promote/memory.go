package promote

import (
	"context"
	"sync"
	"time"
)

// memoryQueue is an in-process Queue for unit tests and the hermetic wiring in
// app.Build. It is NOT durable: everything it holds dies with the process, which
// is exactly what the Valkey queue exists to avoid. Production wiring must use
// NewValkeyQueue.
type memoryQueue struct {
	mu      sync.Mutex
	pending []Job
	claimed map[string]claim
	now     func() time.Time
}

type claim struct {
	job Job
	at  time.Time
}

// NewMemoryQueue returns a non-durable in-process Queue.
func NewMemoryQueue() Queue {
	return &memoryQueue{claimed: make(map[string]claim), now: time.Now}
}

func (q *memoryQueue) Enqueue(_ context.Context, j Job) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = append(q.pending, j)
	return nil
}

func (q *memoryQueue) Claim(_ context.Context) (Job, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return Job{}, false, nil
	}
	j := q.pending[0]
	// Re-slice rather than mutate in place: the popped element must not stay
	// reachable through the backing array.
	q.pending = append([]Job(nil), q.pending[1:]...)
	q.claimed[j.PushID] = claim{job: j, at: q.now().UTC()}
	return j, true, nil
}

func (q *memoryQueue) Ack(_ context.Context, pushID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.claimed, pushID)
	return nil
}

func (q *memoryQueue) Depth(_ context.Context) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending), nil
}

func (q *memoryQueue) Recover(_ context.Context, olderThan time.Duration) ([]Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	cutoff := q.now().UTC().Add(-olderThan)
	var out []Job
	for pushID, c := range q.claimed {
		if c.at.After(cutoff) {
			continue // still held by a live worker
		}
		delete(q.claimed, pushID)
		// Prepended, not appended: a recovered job is the OLDEST work in the queue,
		// so it goes back to the head. The Valkey queue LPUSHes for the same reason.
		q.pending = append([]Job{c.job}, q.pending...)
		out = append(out, c.job)
	}
	return out, nil
}
