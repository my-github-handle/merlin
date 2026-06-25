package policy

import (
	"context"
	"fmt"
)

// FindingsReporter is an optional capability: a policy that produces vulnerability
// findings (e.g. the Trivy scanner) implements it so the engine can aggregate them
// into Result.Findings for the audit trail and response summary.
type FindingsReporter interface {
	ReportedFindings() []Finding
	ScannerDBVersion() string
}

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
		// Collect findings from policies that produce vulnerability reports.
		if reporter, ok := p.(FindingsReporter); ok {
			res.Findings = append(res.Findings, reporter.ReportedFindings()...)
			if dbv := reporter.ScannerDBVersion(); dbv != "" {
				res.TrivyDBVersion = dbv
			}
		}
	}
	if infraErr != nil {
		res.Passed = false
		return res, infraErr
	}
	return res, nil
}
