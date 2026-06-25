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
	w         Writer
	queue     chan job
	onDrop    func(error)
	workerWg  sync.WaitGroup // tracks worker goroutine
	closeOnce sync.Once      // guards close(a.queue) against double-close
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
			if err := a.w.WriteFindings(ctx, j.decision, j.findings); err != nil {
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
// Record never blocks; Flush may block. Neither Record nor Flush may be called concurrently with Close —
// the caller must ensure all producers have stopped before calling Close.
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

// Close stops the worker after draining. The caller MUST ensure no Record or Flush calls
// are in flight or will start during/after Close; Close closes the internal queue, so a concurrent
// send would panic. Close is idempotent.
func (a *Auditor) Close() {
	a.closeOnce.Do(func() { close(a.queue) })
	a.workerWg.Wait()
}
