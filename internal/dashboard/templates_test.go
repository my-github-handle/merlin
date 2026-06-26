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
