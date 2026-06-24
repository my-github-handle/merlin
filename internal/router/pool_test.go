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

type errOutcome struct{}

func (errOutcome) Apply(context.Context, GateRequest, policy.Result, error) error {
	return errors.New("outcome failed")
}

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

func TestPoolReleasesSlotOnGateError(t *testing.T) {
	p := NewPool(New(policy.NewEngine(passPolicy{})), 1) // size 1
	ctx := context.Background()
	// First call: outcome errors. The slot must be released despite the error.
	if err := p.Gate(ctx, GateRequest{}, errOutcome{}); err == nil {
		t.Fatal("expected outcome error from first Gate")
	}
	// If the slot leaked, this second call would block forever; bound it with a deadline.
	done := make(chan error, 1)
	go func() { done <- p.Gate(ctx, GateRequest{}, noopOutcome{}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("second Gate should succeed (slot was released), got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slot leaked: second Gate blocked, pool never released the slot after an errored gate")
	}
}
