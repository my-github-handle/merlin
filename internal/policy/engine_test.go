package policy

import (
	"context"
	"errors"
	"testing"
)

func TestEngineAllPass(t *testing.T) {
	e := NewEngine(
		staticPolicy{name: "a", verdict: Verdict{Passed: true}},
		staticPolicy{name: "b", verdict: Verdict{Passed: true}},
	)
	res, err := e.Run(context.Background(), StagedImage{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Passed {
		t.Error("expected Passed=true when all policies pass")
	}
	if len(res.Verdicts) != 2 {
		t.Errorf("verdicts = %d, want 2", len(res.Verdicts))
	}
}

func TestEngineCollectsAllFailures(t *testing.T) {
	e := NewEngine(
		staticPolicy{name: "a", verdict: Verdict{Passed: false, Reasons: []string{"r-a"}}},
		staticPolicy{name: "b", verdict: Verdict{Passed: false, Reasons: []string{"r-b"}}},
	)
	res, err := e.Run(context.Background(), StagedImage{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Passed {
		t.Error("expected Passed=false")
	}
	if len(res.Verdicts) != 2 {
		t.Errorf("want both verdicts collected, got %v", res.Verdicts)
	}
	if res.Verdicts["a"].Reasons[0] != "r-a" || res.Verdicts["b"].Reasons[0] != "r-b" {
		t.Errorf("reasons not collected from both: %v", res.Verdicts)
	}
}

func TestEnginePolicyErrorIsBlockingInfraFailure(t *testing.T) {
	boom := errors.New("trivy crashed")
	e := NewEngine(
		staticPolicy{name: "ok", verdict: Verdict{Passed: true}},
		staticPolicy{name: "broken", err: boom},
	)
	res, err := e.Run(context.Background(), StagedImage{})
	if err == nil {
		t.Fatal("expected infra error to propagate, got nil")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error should wrap boom, got %v", err)
	}
	if res.Passed {
		t.Error("Result must not pass when a policy errored")
	}
}
