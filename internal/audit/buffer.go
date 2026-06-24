package audit

import (
	"context"
	"sync"

	"github.com/merlin-gate/merlin/internal/policy"
)

type job struct {
	decision Decision
	findings []policy.Finding
	flush    chan struct{} // non-nil only for a Flush marker; worker closes it
}

// Auditor wraps a Writer with an async, non-blocking buffered queue.
type Auditor struct {
	w        Writer
	queue    chan job
	onDrop   func(error)
	workerWg sync.WaitGroup // tracks worker goroutine
}

// NewAuditor starts a background worker draining into w. If the queue is full or
// a write fails, onDrop is called and the push is never blocked.
// IMPORTANT: onDrop must NOT call Record/Flush/Close on the same Auditor (re-entrancy).
func NewAuditor(w Writer, queueSize int, onDrop func(error)) *Auditor {
	a := &Auditor{w: w, queue: make(chan job, queueSize), onDrop: onDrop}
	a.workerWg.Add(1)
	go a.run()
	return a
}

func (a *Auditor) run() {
	defer a.workerWg.Done()
	for j := range a.queue {
		if j.flush != nil {
			close(j.flush)
			continue
		}
		ctx := context.Background()
		if err := a.w.WriteDecision(ctx, j.decision); err != nil {
			a.onDrop(err)
			continue
		}
		if len(j.findings) > 0 {
			if err := a.w.WriteFindings(ctx, j.decision.PushID, j.findings); err != nil {
				a.onDrop(err)
			}
		}
	}
}

// Record enqueues a decision; if the buffer is full it drops (never blocks).
func (a *Auditor) Record(_ context.Context, d Decision, findings []policy.Finding) {
	select {
	case a.queue <- job{decision: d, findings: findings}:
	default:
		a.onDrop(errQueueFull)
	}
}

// Flush blocks until all jobs enqueued before this call have been processed.
// (Flush itself may block; Record never does.) Safe to call concurrently with Record.
func (a *Auditor) Flush(ctx context.Context) {
	marker := make(chan struct{})
	select {
	case a.queue <- job{flush: marker}:
		select {
		case <-marker:
		case <-ctx.Done():
		}
	case <-ctx.Done():
	}
}

// Close stops the worker after draining.
// Must NOT be called concurrently with Record (closes the queue; concurrent Record panics).
func (a *Auditor) Close() {
	close(a.queue)
	a.workerWg.Wait()
}
