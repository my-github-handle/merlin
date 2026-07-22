package audit

import (
	"context"
	"sync"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Per-write robustness. The worker is a single goroutine: without a timeout, one
// hung ClickHouse connection stalls it forever, the queue fills, and every later
// decision is silently dropped. Retries smooth transient outages so audit rows
// (and the report links handed to clients) are not lost to a blip.
// Vars (not consts) so tests can shrink the backoff.
var (
	writeTimeout  = 10 * time.Second
	writeAttempts = 3
	retryBackoff  = 500 * time.Millisecond
)

type job struct {
	decision Decision
	findings []policy.Finding
	alias    *TagAlias     // non-nil only for a tag-alias record
	flush    chan struct{} // non-nil only for a Flush marker; worker closes it
}

// Auditor wraps a Writer with an async, non-blocking buffered queue.
type Auditor struct {
	w         Writer
	queue     chan job
	onDrop    func(Decision, error)
	workerWg  sync.WaitGroup // tracks worker goroutine
	closeOnce sync.Once      // guards close(a.queue) against double-close
}

// NewAuditor starts a background worker draining into w. If the queue is full or
// a write fails, onDrop is called with the affected decision and the push is never
// blocked. Passing the decision lets the callback name which image's audit record
// was lost — a silent drop is how a passed-but-unrecorded scan goes invisible.
// IMPORTANT: onDrop must NOT call Record/Flush/Close on the same Auditor (re-entrancy).
func NewAuditor(w Writer, queueSize int, onDrop func(Decision, error)) *Auditor {
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
		if j.alias != nil {
			if tw, ok := a.w.(TagAliasWriter); ok {
				_ = a.withRetry(func(ctx context.Context) error {
					return tw.WriteTagAlias(ctx, *j.alias)
				})
			}
			continue
		}
		if err := a.withRetry(func(ctx context.Context) error {
			return a.w.WriteDecision(ctx, j.decision)
		}); err != nil {
			a.onDrop(j.decision, err)
			continue
		}
		if len(j.findings) > 0 {
			if err := a.withRetry(func(ctx context.Context) error {
				return a.w.WriteFindings(ctx, j.decision, j.findings)
			}); err != nil {
				// The decision row landed but its findings did not: report as a drop
				// so the operator knows this push's report will render no findings.
				a.onDrop(j.decision, err)
			}
		}
	}
}

// withRetry runs fn with a per-attempt timeout and bounded retries + backoff.
func (a *Auditor) withRetry(fn func(context.Context) error) error {
	var err error
	for attempt := 1; attempt <= writeAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err = fn(ctx)
		cancel()
		if err == nil {
			return nil
		}
		if attempt < writeAttempts {
			time.Sleep(retryBackoff * time.Duration(attempt))
		}
	}
	return err
}

// Record enqueues a decision; if the buffer is full it drops (never blocks).
func (a *Auditor) Record(_ context.Context, d Decision, findings []policy.Finding) {
	select {
	case a.queue <- job{decision: d, findings: findings}:
	default:
		a.onDrop(d, errQueueFull)
	}
}

// RecordTagAlias enqueues a tag -> digest alias (never blocks; dropped when the
// queue is full or the backing Writer does not implement TagAliasWriter).
func (a *Auditor) RecordTagAlias(_ context.Context, alias TagAlias) {
	select {
	case a.queue <- job{alias: &alias}:
	default:
		// Best-effort: a lost alias only degrades report-by-tag lookup, and the
		// by-digest path still works. Reuse onDrop for operator visibility.
		a.onDrop(Decision{Repo: alias.Repo, Tag: alias.Tag, Digest: alias.Digest}, errQueueFull)
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
