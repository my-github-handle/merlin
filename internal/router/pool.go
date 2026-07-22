package router

import (
	"context"
	"errors"

	"github.com/merlin-gate/merlin/internal/policy"
)

// ErrSaturated is returned when the scan pool has no free slot before the
// caller's context deadline. The handler maps it to a retryable 503.
var ErrSaturated = errors.New("router: scan pool saturated")

// Pool bounds the number of concurrent gates (Grype scans) per node.
type Pool struct {
	router *Router
	slots  chan struct{}
}

// NewPool wraps r with a semaphore of the given size (min 1).
func NewPool(r *Router, size int) *Pool {
	if size < 1 {
		size = 1
	}
	return &Pool{router: r, slots: make(chan struct{}, size)}
}

// Acquire blocks until a scan slot frees or ctx is done, returning a release
// func. A deadline expiry while waiting is reported as ErrSaturated (the queue
// never freed a slot in the caller's budget); a cancellation (e.g. the client
// disconnected) is reported as the context's own error, so callers do not
// mislabel a dropped connection as pool saturation.
func (p *Pool) Acquire(ctx context.Context) (release func(), err error) {
	select {
	case p.slots <- struct{}{}:
		return func() { <-p.slots }, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrSaturated
		}
		return nil, ctx.Err()
	}
}

// Router returns the wrapped router, so a caller that manages the slot itself
// (Acquire/release) can run the gate with a scan budget that starts AFTER the
// slot was obtained — queue wait must not consume scan time.
func (p *Pool) Router() *Router { return p.router }

// Gate acquires a slot (respecting ctx), runs the gate, then releases the slot.
// It returns the gate result and any infra error, or ErrSaturated if no slot
// became free before the context deadline. NOTE: ctx bounds BOTH the slot wait
// and the scan; callers that need separate budgets should use Acquire + Router.
func (p *Pool) Gate(ctx context.Context, req GateRequest) (policy.Result, error) {
	release, err := p.Acquire(ctx)
	if err != nil {
		return policy.Result{}, err
	}
	defer release()
	return p.router.Gate(ctx, req)
}
