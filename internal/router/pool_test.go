package router

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

type blockingPolicy struct {
	release chan struct{}
	entered chan struct{}
}

func (b blockingPolicy) Name() string { return "block" }
func (b blockingPolicy) Evaluate(ctx context.Context, _ policy.StagedImage) (policy.Verdict, error) {
	b.entered <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
		return policy.Verdict{}, ctx.Err()
	}
	return policy.Verdict{Passed: true}, nil
}

func TestPoolLimitsConcurrency(t *testing.T) {
	bp := blockingPolicy{release: make(chan struct{}), entered: make(chan struct{}, 2)}
	p := NewPool(New(policy.NewEngine(bp)), 1) // size 1

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = p.Gate(context.Background(), GateRequest{})
	}()
	<-bp.entered // first gate is inside the engine, holding the only slot

	// Second caller must NOT enter while slot is held; give it a short deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := p.Gate(ctx, GateRequest{})
	if !errors.Is(err, ErrSaturated) {
		t.Errorf("expected ErrSaturated while pool full, got %v", err)
	}

	close(bp.release)
	wg.Wait()
}

// errOncePolicy errors on its first Evaluate, then passes. This lets us assert
// the pool releases the slot even when the gate (engine) returns an infra error.
type errOncePolicy struct{ calls int }

func (e *errOncePolicy) Name() string { return "erronce" }
func (e *errOncePolicy) Evaluate(context.Context, policy.StagedImage) (policy.Verdict, error) {
	e.calls++
	if e.calls == 1 {
		return policy.Verdict{}, errors.New("scan failed")
	}
	return policy.Verdict{Passed: true}, nil
}

func TestPoolReleasesSlotOnGateError(t *testing.T) {
	p := NewPool(New(policy.NewEngine(&errOncePolicy{})), 1) // size 1
	ctx := context.Background()
	// First call: the gate errors. The slot must be released despite the error.
	if _, err := p.Gate(ctx, GateRequest{}); err == nil {
		t.Fatal("expected gate error from first Gate")
	}
	// If the slot leaked, this second call would block forever; bound it with a deadline.
	done := make(chan error, 1)
	go func() {
		_, err := p.Gate(ctx, GateRequest{})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("second Gate should succeed (slot was released), got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slot leaked: second Gate blocked, pool never released the slot after an errored gate")
	}
}
