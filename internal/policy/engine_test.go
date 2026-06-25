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

func TestEngineCollectsFindingsFromReporter(t *testing.T) {
	findings := []Finding{
		{CVE: "CVE-2023-1234", Severity: "CRITICAL", Pkg: "libssl", Version: "1.0.0"},
		{CVE: "CVE-2023-5678", Severity: "HIGH", Pkg: "curl", Version: "7.1.0"},
	}
	e := NewEngine(
		staticPolicy{name: "baseline", verdict: Verdict{Passed: true}},
		&findingsReporterPolicy{
			staticPolicy: staticPolicy{name: "trivy", verdict: Verdict{Passed: true}},
			findings:     findings,
			dbVersion:    "db-2023-12-01",
		},
	)
	res, err := e.Run(context.Background(), StagedImage{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Passed {
		t.Error("expected Passed=true")
	}
	if len(res.Findings) != 2 {
		t.Errorf("findings = %d, want 2", len(res.Findings))
	}
	if res.Findings[0].CVE != "CVE-2023-1234" {
		t.Errorf("first finding CVE = %q, want CVE-2023-1234", res.Findings[0].CVE)
	}
	if res.TrivyDBVersion != "db-2023-12-01" {
		t.Errorf("TrivyDBVersion = %q, want db-2023-12-01", res.TrivyDBVersion)
	}
}

func TestEngineCollectsFindingsOnBothPassAndFail(t *testing.T) {
	findings := []Finding{
		{CVE: "CVE-2023-9999", Severity: "CRITICAL", Pkg: "zlib", Version: "1.2.3"},
	}
	e := NewEngine(
		&findingsReporterPolicy{
			staticPolicy: staticPolicy{name: "trivy", verdict: Verdict{Passed: false, Reasons: []string{"blocking CVE"}}},
			findings:     findings,
			dbVersion:    "db-2024-01-01",
		},
	)
	res, err := e.Run(context.Background(), StagedImage{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Passed {
		t.Error("expected Passed=false when policy fails")
	}
	if len(res.Findings) != 1 {
		t.Errorf("findings = %d, want 1 (even when policy fails)", len(res.Findings))
	}
	if res.Findings[0].CVE != "CVE-2023-9999" {
		t.Errorf("finding CVE = %q, want CVE-2023-9999", res.Findings[0].CVE)
	}
}

func TestEnginePolicyWithoutFindingsReporter(t *testing.T) {
	e := NewEngine(
		staticPolicy{name: "baseline", verdict: Verdict{Passed: true}},
		staticPolicy{name: "distro", verdict: Verdict{Passed: true}},
	)
	res, err := e.Run(context.Background(), StagedImage{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Passed {
		t.Error("expected Passed=true")
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %d, want 0 (no policy implements FindingsReporter)", len(res.Findings))
	}
	if res.TrivyDBVersion != "" {
		t.Errorf("TrivyDBVersion = %q, want empty string", res.TrivyDBVersion)
	}
}

// findingsReporterPolicy is a test double implementing FindingsReporter.
type findingsReporterPolicy struct {
	staticPolicy
	findings  []Finding
	dbVersion string
}

func (f *findingsReporterPolicy) ReportedFindings() []Finding { return f.findings }
func (f *findingsReporterPolicy) ScannerDBVersion() string    { return f.dbVersion }
