package dashboard

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderActivity(t *testing.T) {
	rnd, err := NewRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	vm := ActivityVM{
		Range:  Range7d,
		Stats:  StatsVM{Total: 10, Passed: 8, Rejected: 2, PassRate: 80},
		Recent: []DecisionVM{{Repo: "a/b", Tag: "v1", Passed: true, Identity: "ci"}},
	}
	var buf bytes.Buffer
	if err := rnd.Render(&buf, "activity", vm); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"a/b", "80", "Activity"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestRenderReportEmptyState(t *testing.T) {
	rnd, err := NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := rnd.Render(&buf, "report", ReportVM{Found: false}); err != nil {
		t.Fatalf("render empty report: %v", err)
	}
	if !strings.Contains(buf.String(), "No report") {
		t.Error("empty report should show a 'No report' message")
	}
}

func TestRenderDegradedActivity(t *testing.T) {
	rnd, _ := NewRenderer()
	var buf bytes.Buffer
	// Errored, empty data must not panic and must render valid (non-empty) HTML.
	if err := rnd.Render(&buf, "activity", ActivityVM{Range: Range1d, Errored: true}); err != nil {
		t.Fatalf("render degraded: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("degraded render produced no output")
	}
}

func TestRenderHealth(t *testing.T) {
	rnd, err := NewRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	vm := HealthVM{
		Range:          Range7d,
		Stats:          StatsVM{Total: 10, Passed: 8, Rejected: 2, PassRate: 80},
		TrivyDBAgeDays: 0.5,
		ACRPushSuccess: 99.5,
		PushErrors:     0,
		BaseImages: []BaseImageVM{
			{BaseImageID: "alpine:3.16", Total: 5, Passed: 4, PassRate: 80},
		},
	}
	var buf bytes.Buffer
	if err := rnd.Render(&buf, "health", vm); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"alpine:3.16", "80", "Health"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestRenderHealthDegraded(t *testing.T) {
	rnd, _ := NewRenderer()
	var buf bytes.Buffer
	// Errored, empty data must not panic and must render valid (non-empty) HTML.
	if err := rnd.Render(&buf, "health", HealthVM{Range: Range1d, Errored: true}); err != nil {
		t.Fatalf("render degraded: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("degraded render produced no output")
	}
}

func TestRenderVulnerabilities(t *testing.T) {
	rnd, err := NewRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	vm := VulnVM{
		Range:    Range7d,
		Severity: SeverityVM{Critical: 2, High: 5, Medium: 10, Low: 20, Unknown: 1},
		TopCVEs: []CVEVM{
			{CVE: "CVE-2021-12345", Severity: "Critical", Pkg: "openssl", FixedVersion: "1.1.1l", ImageCount: 3},
		},
		Fix: FixVM{
			BySeverity: []FixRowVM{
				{Severity: "Critical", Total: 2, Fixable: 2, Pct: 100},
			},
			TopFixable: []CVEVM{
				{CVE: "CVE-2021-12345", Severity: "Critical", Pkg: "openssl", FixedVersion: "1.1.1l", ImageCount: 3},
			},
		},
	}
	var buf bytes.Buffer
	if err := rnd.Render(&buf, "vulnerabilities", vm); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"CVE-2021-12345", "Critical", "openssl"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestRenderVulnerabilitiesDegraded(t *testing.T) {
	rnd, _ := NewRenderer()
	var buf bytes.Buffer
	// Errored, empty data must not panic and must render valid (non-empty) HTML.
	if err := rnd.Render(&buf, "vulnerabilities", VulnVM{Range: Range1d, Errored: true}); err != nil {
		t.Fatalf("render degraded: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("degraded render produced no output")
	}
}

func TestRenderIdentities(t *testing.T) {
	rnd, err := NewRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	vm := IdentitiesVM{
		Range: Range7d,
		Identities: []EntityVM{
			{Name: "ci-bot", Total: 10, Passed: 8, PassRate: 80},
		},
		Repos: []EntityVM{
			{Name: "myorg/myrepo", Total: 10, Passed: 8, PassRate: 80},
		},
	}
	var buf bytes.Buffer
	if err := rnd.Render(&buf, "identities", vm); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ci-bot", "myorg/myrepo", "80"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestRenderIdentitiesDegraded(t *testing.T) {
	rnd, _ := NewRenderer()
	var buf bytes.Buffer
	// Errored, empty data must not panic and must render valid (non-empty) HTML.
	if err := rnd.Render(&buf, "identities", IdentitiesVM{Range: Range1d, Errored: true}); err != nil {
		t.Fatalf("render degraded: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("degraded render produced no output")
	}
}
