package trivy

import (
	"context"
	"fmt"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Runner runs a Trivy scan against an on-disk OCI layout.
type Runner interface {
	Scan(ctx context.Context, ociPath string) (Report, error)
}

// Policy is the Trivy vulnerability-scan policy.
type Policy struct {
	runner     Runner
	threshold  string
	lastReport Report
}

// severityRank orders severities so we can compare against a threshold.
var severityRank = map[string]int{
	"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

// New builds a Trivy policy that fails on findings at/above threshold.
func New(runner Runner, threshold string) *Policy {
	return &Policy{runner: runner, threshold: threshold}
}

func (p *Policy) Name() string { return "trivy" }

// LastReport returns the most recent scan report (findings + DB version).
func (p *Policy) LastReport() Report { return p.lastReport }

func (p *Policy) Evaluate(ctx context.Context, img policy.StagedImage) (policy.Verdict, error) {
	rep, err := p.runner.Scan(ctx, img.OCIPath)
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("trivy scan: %w", err)
	}
	p.lastReport = rep
	min := severityRank[p.threshold]
	var reasons []string
	for _, f := range rep.Findings {
		if severityRank[f.Severity] >= min {
			reasons = append(reasons, fmt.Sprintf("%s (%s) in %s %s", f.CVE, f.Severity, f.Pkg, f.Version))
		}
	}
	if len(reasons) > 0 {
		return policy.Verdict{Passed: false, Reasons: reasons}, nil
	}
	return policy.Verdict{Passed: true}, nil
}
