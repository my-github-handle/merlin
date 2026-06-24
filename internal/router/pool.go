package router

import (
	"context"
	"errors"
)

// ErrSaturated is returned when the scan pool has no free slot before the
// caller's context deadline. The handler maps it to a retryable 503.
var ErrSaturated = errors.New("router: scan pool saturated")

// Pool bounds the number of concurrent gates (Trivy scans) per node.
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

// Gate acquires a slot (respecting ctx), runs the gate, then releases the slot.
func (p *Pool) Gate(ctx context.Context, req GateRequest, outcome Outcome) error {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
		return p.router.Gate(ctx, req, outcome)
	case <-ctx.Done():
		return ErrSaturated
	}
}
