package policy

import (
	"context"
	"testing"
)

func TestVerdictZeroValueIsFailed(t *testing.T) {
	var v Verdict
	if v.Passed {
		t.Error("zero-value Verdict should not be Passed")
	}
}

// staticPolicy is a test double implementing Policy.
type staticPolicy struct {
	name    string
	verdict Verdict
	err     error
}

func (s staticPolicy) Name() string { return s.name }
func (s staticPolicy) Evaluate(_ context.Context, _ StagedImage) (Verdict, error) {
	return s.verdict, s.err
}

func TestPolicyInterfaceSatisfied(t *testing.T) {
	var _ Policy = staticPolicy{name: "x"}
	p := staticPolicy{name: "trivy", verdict: Verdict{Passed: true}}
	if p.Name() != "trivy" {
		t.Errorf("Name() = %q, want trivy", p.Name())
	}
}
