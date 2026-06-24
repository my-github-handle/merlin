package trivy

import "testing"

const sampleJSON = `{
  "Metadata": {"DBVersion": "2024-06-23"},
  "Results": [
    {
      "Target": "app",
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2024-1","Severity":"CRITICAL","PkgName":"openssl","InstalledVersion":"1.1.1","FixedVersion":"1.1.1w"},
        {"VulnerabilityID":"CVE-2024-2","Severity":"HIGH","PkgName":"zlib","InstalledVersion":"1.2.0","FixedVersion":""}
      ]
    }
  ]
}`

func TestParseReportExtractsFindingsAndDBVersion(t *testing.T) {
	r, err := ParseReport([]byte(sampleJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.DBVersion != "2024-06-23" {
		t.Errorf("DBVersion = %q, want 2024-06-23", r.DBVersion)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(r.Findings))
	}
	if r.Findings[0].CVE != "CVE-2024-1" || r.Findings[0].Severity != "CRITICAL" {
		t.Errorf("finding[0] = %+v", r.Findings[0])
	}
	if r.Findings[0].Pkg != "openssl" || r.Findings[0].Version != "1.1.1" {
		t.Errorf("finding[0] pkg/version = %+v", r.Findings[0])
	}
}

func TestParseReportHandlesNoVulnerabilities(t *testing.T) {
	r, err := ParseReport([]byte(`{"Metadata":{"DBVersion":"x"},"Results":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(r.Findings))
	}
}

func TestParseReportRejectsInvalidJSON(t *testing.T) {
	if _, err := ParseReport([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
