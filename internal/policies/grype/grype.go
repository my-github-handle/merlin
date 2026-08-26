package grype

import (
	"context"
	"fmt"
	"strings"
	"time"

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
	dbAge     DBAgeObserver
	now       func() time.Time
	// Scan cache (see reportcache.go). Nil cache means every push scans, which is
	// the behaviour this type had before the cache existed.
	cache         ReportStore
	cacheMaxDBAge time.Duration
	cacheObserver ScanCacheObserver
}

// DBAgeObserver receives the age of the scanner's vulnerability DB, in days.
// observability.Metrics satisfies it.
//
// The gauge behind it existed and was rendered on the dashboard long before
// anything set it, which is worse than not having it: an unset gauge reads as
// "0 days old" — the healthiest possible value — so a scanner whose DB had stopped
// updating (and was therefore passing images with known CVEs) looked perfectly
// fresh. The grype policy is the only component that knows the DB's build date, so
// the observation belongs here.
type DBAgeObserver interface {
	SetScannerDBAgeDays(days float64)
}

// Option configures a Policy.
type Option func(*Policy)

// WithDBAgeObserver reports the scanner DB's age after every scan. Nil is a no-op.
func WithDBAgeObserver(o DBAgeObserver) Option { return func(p *Policy) { p.dbAge = o } }

// withClock overrides the clock used to derive the DB age. Unexported: only the
// tests need a fixed now.
func withClock(now func() time.Time) Option { return func(p *Policy) { p.now = now } }

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

// observeDBAge publishes the DB's age in days.
//
// A zero built time is left UNREPORTED rather than published as zero days: zero is
// the freshest value the gauge can hold, so writing it on missing data would hide
// exactly the condition the metric exists to catch. A build time in the future
// (pod/DB clock skew) is clamped to zero, since a negative age breaks any
// "older than N days" comparison.
func (p *Policy) observeDBAge(built time.Time) {
	if p.dbAge == nil || built.IsZero() {
		return
	}
	age := p.clock()().Sub(built)
	if age < 0 {
		age = 0
	}
	p.dbAge.SetScannerDBAgeDays(age.Hours() / 24)
}

func (p *Policy) Evaluate(ctx context.Context, img policy.StagedImage) (policy.Verdict, error) {
	if img.OCIPath == "" {
		return policy.Verdict{}, fmt.Errorf("grype scan: empty OCI path for image")
	}
	rep, err := p.scanOrReuse(ctx, img)
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("grype scan: %w", err)
	}
	// Every evaluation re-reports the age, including one served from the scan cache
	// — the report carries the build time of the DB it was produced with, so a reused
	// report still describes a real DB. Skipping this on a cache hit would let the
	// gauge go stale exactly when reuse is working, and an unset gauge reads as
	// "0 days old": the healthiest possible value.
	p.observeDBAge(rep.DBBuilt)
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
