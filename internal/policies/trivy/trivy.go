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

// Policy is the Trivy vulnerability-scan policy. It is stateless across calls:
// each Evaluate carries its findings back through the returned Verdict, so the
// same Policy is safe to use from concurrent gates.
type Policy struct {
	runner    Runner
	threshold string
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

func (p *Policy) Evaluate(ctx context.Context, img policy.StagedImage) (policy.Verdict, error) {
	if img.OCIPath == "" {
		return policy.Verdict{}, fmt.Errorf("trivy scan: empty OCI path for image")
	}
	rep, err := p.runner.Scan(ctx, img.OCIPath)
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("trivy scan: %w", err)
	}
	min := severityRank[p.threshold]
	var reasons []string
	for _, f := range rep.Findings {
		rank, known := severityRank[f.Severity]
		if !known {
			// Unrecognized severity: fail closed — never silently drop a finding.
			reasons = append(reasons, fmt.Sprintf("%s (unrecognized severity %q) in %s %s", f.CVE, f.Severity, f.Pkg, f.Version))
			continue
		}
		if rank >= min {
			reasons = append(reasons, fmt.Sprintf("%s (%s) in %s %s", f.CVE, f.Severity, f.Pkg, f.Version))
		}
	}
	return policy.Verdict{
		Passed:           len(reasons) == 0,
		Reasons:          reasons,
		Findings:         rep.Findings,
		ScannerDBVersion: rep.DBVersion,
	}, nil
}
