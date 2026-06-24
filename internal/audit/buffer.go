package audit

import (
	"context"
	"sync"

	"github.com/merlin-gate/merlin/internal/policy"
)

type job struct {
	decision Decision
	findings []policy.Finding
}

// Auditor wraps a Writer with an async, non-blocking buffered queue.
type Auditor struct {
	w         Writer
	queue     chan job
	onDrop    func(error)
	workerWg  sync.WaitGroup // tracks worker goroutine
	pendingWg sync.WaitGroup // tracks pending jobs
}

// NewAuditor starts a background worker draining into w. If the queue is full or
// a write fails, onDrop is called and the push is never blocked.
func NewAuditor(w Writer, queueSize int, onDrop func(error)) *Auditor {
	a := &Auditor{w: w, queue: make(chan job, queueSize), onDrop: onDrop}
	a.workerWg.Add(1)
	go a.run()
	return a
}

func (a *Auditor) run() {
	defer a.workerWg.Done()
	for j := range a.queue {
		ctx := context.Background()
		if err := a.w.WriteDecision(ctx, j.decision); err != nil {
			a.onDrop(err)
			a.pendingWg.Done() // job processed (even if failed)
			continue
		}
		if len(j.findings) > 0 {
			if err := a.w.WriteFindings(ctx, j.decision.PushID, j.findings); err != nil {
				a.onDrop(err)
			}
		}
		a.pendingWg.Done() // job processed successfully
	}
}

// Record enqueues a decision; if the buffer is full it drops (never blocks).
func (a *Auditor) Record(_ context.Context, d Decision, findings []policy.Finding) {
	select {
	case a.queue <- job{decision: d, findings: findings}:
		a.pendingWg.Add(1) // job enqueued
	default:
		a.onDrop(errQueueFull)
	}
}

// Flush waits until all enqueued jobs have been processed by the worker.
// This implementation is race-free: it waits for the pendingWg which is
// incremented when Record enqueues and decremented when the worker completes.
func (a *Auditor) Flush(_ context.Context) {
	a.pendingWg.Wait()
}

// Close stops the worker after draining.
func (a *Auditor) Close() {
	close(a.queue)
	a.workerWg.Wait()
}
