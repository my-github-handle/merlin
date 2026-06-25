package trivy

import "testing"

const sampleJSON = `{
  "SchemaVersion": 2,
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
	r, err := ParseReport([]byte(`{"SchemaVersion":2,"Metadata":{"DBVersion":"x"},"Results":[]}`))
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

func TestParseReportRejectsMissingSchemaVersion(t *testing.T) {
	if _, err := ParseReport([]byte(`{}`)); err == nil {
		t.Fatal("expected error for missing SchemaVersion")
	}
}

func TestParseReportEmptySeverityBecomesUNKNOWN(t *testing.T) {
	const emptySevJSON = `{
	  "SchemaVersion": 2,
	  "Metadata": {"DBVersion": "2024-06-24"},
	  "Results": [
	    {
	      "Vulnerabilities": [
	        {"VulnerabilityID":"CVE-EMPTY","Severity":"","PkgName":"pkg1","InstalledVersion":"1.0.0"},
	        {"VulnerabilityID":"CVE-WHITESPACE","Severity":"  ","PkgName":"pkg2","InstalledVersion":"2.0.0"}
	      ]
	    }
	  ]
	}`
	r, err := ParseReport([]byte(emptySevJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(r.Findings))
	}
	if r.Findings[0].Severity != "UNKNOWN" {
		t.Errorf("empty severity finding[0].Severity = %q, want UNKNOWN", r.Findings[0].Severity)
	}
	if r.Findings[1].Severity != "UNKNOWN" {
		t.Errorf("whitespace severity finding[1].Severity = %q, want UNKNOWN", r.Findings[1].Severity)
	}
}
