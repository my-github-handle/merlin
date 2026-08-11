package grype

import (
	"context"
	"fmt"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Runner runs a Grype scan against an on-disk OCI layout.
type Runner interface {
	Scan(ctx context.Context, ociPath string) (Report, error)
}

// Policy is the Grype vulnerability-scan policy. Stateless across calls: each
// Evaluate carries its findings back through the returned Verdict, so the same
// Policy is safe to use from concurrent gates.
type Policy struct {
	runner    Runner
	threshold string
	observe   bool
}

// Option configures a Policy.
type Option func(*Policy)

// unenforcedPrefix marks a reason that was recorded but did NOT block the push.
// The engine keys Result.Unenforced off any reason on a passing verdict, and the
// push summary refuses to say "clean" when one is present, so this prefix is the
// difference between "no critical findings" and "critical findings, published
// anyway" everywhere downstream.
const unenforcedPrefix = "not enforced: "

// Observe makes the scan report without gating: findings at or above the
// threshold are recorded on the Verdict and in the audit store, but the verdict
// passes and the image is published. Intended as a temporary posture while the
// push path is being fixed — not a steady state, since it lets a Critical CVE
// reach the registry. Enforcement is the default; this must be asked for.
func Observe() Option { return func(p *Policy) { p.observe = true } }

// severityRank orders Grype severities so we can compare against a threshold.
// Grype casing is title-case (e.g. "Critical"); the threshold arrives upper-case
// from config, so both are upper-cased before lookup.
var severityRank = map[string]int{
	"UNKNOWN": 0, "NEGLIGIBLE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5,
}

// New builds a Grype policy that fails on findings at/above threshold. Pass
// Observe() to report those findings without failing the push.
func New(runner Runner, threshold string, opts ...Option) *Policy {
	p := &Policy{runner: runner, threshold: threshold}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Policy) Name() string { return "grype" }

func (p *Policy) Evaluate(ctx context.Context, img policy.StagedImage) (policy.Verdict, error) {
	if img.OCIPath == "" {
		return policy.Verdict{}, fmt.Errorf("grype scan: empty OCI path for image")
	}
	rep, err := p.runner.Scan(ctx, img.OCIPath)
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("grype scan: %w", err)
	}
	min := severityRank[strings.ToUpper(p.threshold)]
	var reasons []string
	for _, f := range rep.Findings {
		rank, known := severityRank[strings.ToUpper(f.Severity)]
		if !known {
			// Unrecognized severity: fail closed — never silently drop a finding.
			reasons = append(reasons, fmt.Sprintf("%s (unrecognized severity %q) in %s %s", f.CVE, f.Severity, f.Pkg, f.Version))
			continue
		}
		if rank >= min {
			reasons = append(reasons, fmt.Sprintf("%s (%s) in %s %s", f.CVE, f.Severity, f.Pkg, f.Version))
		}
	}
	if p.observe {
		// Report, never gate. This covers the unrecognized-severity path above too:
		// a mode that still rejects a subset of images is not observe mode. Reasons
		// are kept (prefixed) so the audit row and push summary can still say what
		// would have blocked — dropping them here would publish the image AND erase
		// the evidence.
		for i := range reasons {
			reasons[i] = unenforcedPrefix + reasons[i]
		}
		return policy.Verdict{
			Passed:           true,
			Reasons:          reasons,
			Findings:         rep.Findings,
			ScannerDBVersion: rep.DBVersion,
		}, nil
	}
	return policy.Verdict{
		Passed:           len(reasons) == 0,
		Reasons:          reasons,
		Findings:         rep.Findings,
		ScannerDBVersion: rep.DBVersion,
	}, nil
}
