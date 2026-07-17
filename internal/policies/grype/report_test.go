package grype

import (
	"os"
	"strings"
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
	if !strings.Contains(rep.DBVersion, "v6.1.9") {
		t.Errorf("DBVersion should contain v6.1.9, got: %s", rep.DBVersion)
	}
	if rep.DBVersion == "schema 0 built " {
		t.Error("DBVersion should not be the old bug pattern")
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

func TestParseReportEmptySeverityBecomesUnknown(t *testing.T) {
	raw := []byte(`{
		"matches": [{
			"vulnerability": { "id": "CVE-2024-9999", "severity": "", "fix": { "versions": [] } },
			"artifact": { "name": "pkg", "version": "1.0" }
		}],
		"descriptor": { "db": { "status": { "schemaVersion": "v6.1.9", "built": "2026-07-17T00:00:00Z" } } }
	}`)
	rep, err := ParseReport(raw)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(rep.Findings))
	}
	if rep.Findings[0].Severity != "UNKNOWN" {
		t.Errorf("empty severity should become UNKNOWN, got: %s", rep.Findings[0].Severity)
	}
}

func TestParseReportMultipleFixVersionsTakesFirst(t *testing.T) {
	raw := []byte(`{
		"matches": [{
			"vulnerability": {
				"id": "CVE-2024-8888",
				"severity": "High",
				"fix": { "versions": ["1.0.0", "2.0.0"] }
			},
			"artifact": { "name": "pkg", "version": "0.9.0" }
		}],
		"descriptor": { "db": { "status": { "schemaVersion": "v6.1.9", "built": "2026-07-17T00:00:00Z" } } }
	}`)
	rep, err := ParseReport(raw)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(rep.Findings))
	}
	if rep.Findings[0].FixedVersion != "1.0.0" {
		t.Errorf("multiple fix versions should take first, got: %s", rep.Findings[0].FixedVersion)
	}
}
