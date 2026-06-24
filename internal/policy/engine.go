package policy

import (
	"context"
	"fmt"
)

// Engine runs a fixed, ordered set of policies against a staged image.
type Engine struct {
	policies []Policy
}

// NewEngine builds an engine from the given policies, run in order.
func NewEngine(policies ...Policy) *Engine {
	return &Engine{policies: policies}
}

// Run executes every policy (no short-circuit), collecting all verdicts.
// Result.Passed is the AND of all verdicts. If any policy returns an error,
// that is a blocking infra failure: Run returns the (wrapped) error and a
// Result with Passed=false.
func (e *Engine) Run(ctx context.Context, img StagedImage) (Result, error) {
	res := Result{Passed: true, Verdicts: make(map[string]Verdict)}
	var infraErr error
	for _, p := range e.policies {
		v, err := p.Evaluate(ctx, img)
		if err != nil {
			infraErr = fmt.Errorf("policy %q could not run: %w", p.Name(), err)
			res.Passed = false
			continue
		}
		res.Verdicts[p.Name()] = v
		if !v.Passed {
			res.Passed = false
		}
	}
	if infraErr != nil {
		res.Passed = false
		return res, infraErr
	}
	return res, nil
}
