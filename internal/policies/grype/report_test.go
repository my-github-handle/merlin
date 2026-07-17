package grype

import (
	"os"
	"testing"
)

func TestParseReportGrypeJSON(t *testing.T) {
	raw, err := os.ReadFile("testdata/grype-sample.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	rep, err := ParseReport(raw)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if rep.DBVersion == "" {
		t.Error("DBVersion should be populated from descriptor.db")
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(rep.Findings))
	}
	f0 := rep.Findings[0]
	// Parser normalizes severity to UPPER-CASE (matches CH enum + ranking keys).
	if f0.CVE != "CVE-2024-0001" || f0.Severity != "CRITICAL" ||
		f0.Pkg != "openssl" || f0.Version != "1.1.1k-r0" || f0.FixedVersion != "1.1.1w-r0" {
		t.Errorf("finding0 mismatch: %+v", f0)
	}
	f1 := rep.Findings[1]
	if f1.Severity != "NEGLIGIBLE" || f1.FixedVersion != "" {
		t.Errorf("finding1 (negligible, no fix) mismatch: %+v", f1)
	}
}

func TestParseReportRejectsNonGrypeJSON(t *testing.T) {
	if _, err := ParseReport([]byte(`{"foo":1}`)); err == nil {
		t.Error("expected error for JSON lacking matches/descriptor")
	}
}
