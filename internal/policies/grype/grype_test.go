package grype

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

func (f fakeRunner) Scan(_ context.Context, _ string) (Report, error) { return f.report, f.err }

func TestNameIsGrype(t *testing.T) {
	if New(fakeRunner{}, "CRITICAL").Name() != "grype" {
		t.Error("Name() should be grype")
	}
}

func TestEvaluateFailsOnCritical(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-1", Severity: "Critical", Pkg: "openssl", Version: "1.1.1"},
	}}}
	v, err := New(r, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed || len(v.Reasons) != 1 {
		t.Errorf("expected fail with 1 reason, got passed=%v reasons=%v", v.Passed, v.Reasons)
	}
}

func TestEvaluatePassesWhenBelowThreshold(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-2", Severity: "High", Pkg: "zlib", Version: "1.2.0"},
		{CVE: "CVE-3", Severity: "Negligible", Pkg: "p", Version: "1"},
	}}}
	v, err := New(r, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed {
		t.Errorf("expected pass when only High/Negligible present, reasons=%v", v.Reasons)
	}
}

func TestEvaluateNegligibleThreshold(t *testing.T) {
	// Threshold NEGLIGIBLE: even a Negligible finding fails.
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-4", Severity: "Negligible", Pkg: "p", Version: "1"},
	}}}
	v, _ := New(r, "NEGLIGIBLE").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if v.Passed {
		t.Error("Negligible finding must fail when threshold is NEGLIGIBLE")
	}
}

func TestEvaluateFailsClosedOnUnrecognizedSeverity(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-X", Severity: "WEIRD", Pkg: "p", Version: "1"},
	}}}
	v, _ := New(r, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if v.Passed {
		t.Error("unrecognized severity must fail closed")
	}
}

func TestEvaluateRunnerErrorIsInfraFailure(t *testing.T) {
	boom := errors.New("grype exited 2")
	_, err := New(fakeRunner{err: boom}, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if !errors.Is(err, boom) {
		t.Errorf("expected wrapped runner error, got %v", err)
	}
}

func TestEvaluateEmptyOCIPathIsError(t *testing.T) {
	_, err := New(fakeRunner{}, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: ""})
	if err == nil {
		t.Error("empty OCIPath must return an error")
	}
}

func TestVerdictCarriesFindings(t *testing.T) {
	findings := []policy.Finding{
		{CVE: "CVE-2024-1111", Severity: "Critical", Pkg: "curl", Version: "8.0.0"},
		{CVE: "CVE-2024-2222", Severity: "High", Pkg: "nginx", Version: "1.24.0"},
	}
	r := fakeRunner{report: Report{Findings: findings, DBVersion: "schema 5 built 2026-07-16"}}
	v, err := New(r, "HIGH").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(v.Findings) != 2 || v.Findings[0].CVE != "CVE-2024-1111" {
		t.Errorf("verdict findings mismatch: %+v", v.Findings)
	}
	if v.ScannerDBVersion != "schema 5 built 2026-07-16" {
		t.Errorf("ScannerDBVersion = %q", v.ScannerDBVersion)
	}
}
