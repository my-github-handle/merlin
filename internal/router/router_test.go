package router

import (
	"context"
	"errors"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

type passPolicy struct{}

func (passPolicy) Name() string { return "p" }
func (passPolicy) Evaluate(context.Context, policy.StagedImage) (policy.Verdict, error) {
	return policy.Verdict{Passed: true}, nil
}

type errPolicy struct{}

func (errPolicy) Name() string { return "e" }
func (errPolicy) Evaluate(context.Context, policy.StagedImage) (policy.Verdict, error) {
	return policy.Verdict{}, errors.New("scan crashed")
}

func TestGateReturnsPassingResult(t *testing.T) {
	r := New(policy.NewEngine(passPolicy{}))
	res, err := r.Gate(context.Background(), GateRequest{Source: "docker"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Errorf("expected passing result, got %+v", res)
	}
}

func TestGateReturnsInfraError(t *testing.T) {
	r := New(policy.NewEngine(errPolicy{}))
	// Gate returns the engine's infra error directly to the caller (the handler),
	// which decides the response. The result must not pass on an infra error.
	res, err := r.Gate(context.Background(), GateRequest{Source: "docker"})
	if err == nil {
		t.Fatal("expected infra error from Gate")
	}
	if res.Passed {
		t.Error("result should not pass on infra error")
	}
}
