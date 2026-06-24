package trivy

import (
	"context"
	"errors"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

type fakeRunner struct {
	report Report
	err    error
}

func (f fakeRunner) Scan(_ context.Context, _ string) (Report, error) {
	return f.report, f.err
}

func TestEvaluateFailsOnCritical(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-1", Severity: "CRITICAL", Pkg: "openssl", Version: "1.1.1"},
	}}}
	p := New(r, "CRITICAL")
	v, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed {
		t.Error("expected Passed=false on CRITICAL finding")
	}
	if len(v.Reasons) != 1 {
		t.Fatalf("reasons = %v, want 1", v.Reasons)
	}
}

func TestEvaluatePassesWhenBelowThreshold(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-2", Severity: "HIGH", Pkg: "zlib", Version: "1.2.0"},
	}}}
	p := New(r, "CRITICAL")
	v, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed {
		t.Errorf("expected Passed=true when only HIGH present, reasons=%v", v.Reasons)
	}
}

func TestEvaluateRunnerErrorIsInfraFailure(t *testing.T) {
	boom := errors.New("trivy exited 2")
	p := New(fakeRunner{err: boom}, "CRITICAL")
	_, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if !errors.Is(err, boom) {
		t.Errorf("expected wrapped runner error, got %v", err)
	}
}

func TestNameIsTrivy(t *testing.T) {
	if New(fakeRunner{}, "CRITICAL").Name() != "trivy" {
		t.Error("Name() should be trivy")
	}
}

func TestEvaluateFailsClosedOnUnrecognizedSeverity(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-X", Severity: "WEIRD", Pkg: "p", Version: "1"},
	}}}
	v, err := New(r, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed {
		t.Error("unrecognized severity must fail closed (not pass)")
	}
}

func TestEvaluateEmptyOCIPathIsError(t *testing.T) {
	r := fakeRunner{report: Report{}}
	_, err := New(r, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: ""})
	if err == nil {
		t.Error("empty OCIPath must return an error, not pass")
	}
}
