package policy

import (
	"context"
	"errors"
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
	var infraErrs []error
	for _, p := range e.policies {
		v, err := p.Evaluate(ctx, img)
		if err != nil {
			// Collect EVERY policy error (errors.Join below): overwriting would
			// hide all but the last failure from logs and the audit error detail.
			infraErrs = append(infraErrs, fmt.Errorf("policy %q could not run: %w", p.Name(), err))
			res.Passed = false
			continue
		}
		res.Verdicts[p.Name()] = v
		if !v.Passed {
			res.Passed = false
		}
		// Collect findings carried back on the verdict (request-local, no shared state).
		res.Findings = append(res.Findings, v.Findings...)
		if v.ScannerDBVersion != "" {
			res.ScannerDBVersion = v.ScannerDBVersion
		}
		if v.Age != nil {
			res.Age = v.Age
		}
	}
	if len(infraErrs) > 0 {
		res.Passed = false
		return res, errors.Join(infraErrs...)
	}
	return res, nil
}
