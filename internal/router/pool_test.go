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

type noopOutcome struct{}

func (noopOutcome) Apply(context.Context, GateRequest, policy.Result, error) error { return nil }

func TestPoolLimitsConcurrency(t *testing.T) {
	bp := blockingPolicy{release: make(chan struct{}), entered: make(chan struct{}, 2)}
	p := NewPool(New(policy.NewEngine(bp)), 1) // size 1

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = p.Gate(context.Background(), GateRequest{}, noopOutcome{})
	}()
	<-bp.entered // first gate is inside the engine, holding the only slot

	// Second caller must NOT enter while slot is held; give it a short deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := p.Gate(ctx, GateRequest{}, noopOutcome{})
	if !errors.Is(err, ErrSaturated) {
		t.Errorf("expected ErrSaturated while pool full, got %v", err)
	}

	close(bp.release)
	wg.Wait()
}
