package router

import (
	"context"
	"errors"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

type recordingOutcome struct {
	res     policy.Result
	gateErr error
	called  bool
}

func (o *recordingOutcome) Apply(_ context.Context, _ GateRequest, res policy.Result, gateErr error) error {
	o.called = true
	o.res = res
	o.gateErr = gateErr
	return nil
}

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

func TestGatePassHandedToOutcome(t *testing.T) {
	r := New(policy.NewEngine(passPolicy{}))
	o := &recordingOutcome{}
	if err := r.Gate(context.Background(), GateRequest{Source: "docker"}, o); err != nil {
		t.Fatal(err)
	}
	if !o.called || !o.res.Passed {
		t.Errorf("outcome not called with passing result: %+v", o)
	}
}

func TestGateInfraErrorHandedToOutcome(t *testing.T) {
	r := New(policy.NewEngine(errPolicy{}))
	o := &recordingOutcome{}
	// Gate must NOT surface the engine's infra error to its caller; it hands the
	// error to the outcome adapter, which decides the response. Gate returns
	// whatever the outcome returns (nil here), so the error must arrive via
	// o.gateErr, not as Gate's return value.
	if err := r.Gate(context.Background(), GateRequest{Source: "docker"}, o); err != nil {
		t.Fatalf("Gate should return the outcome's result (nil here), not the gate error: %v", err)
	}
	if o.gateErr == nil {
		t.Error("expected gateErr to be passed to outcome")
	}
	if o.res.Passed {
		t.Error("result should not pass on infra error")
	}
}
