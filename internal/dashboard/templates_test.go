package dashboard

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderOverview(t *testing.T) {
	rnd, err := NewRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	vm := OverviewVM{
		Range:          Range7d,
		Stats:          StatsVM{Total: 10, Passed: 8, Rejected: 2, PassRate: 80, P95: 14200},
		TrivyDBAgeDays: 4, ACRPushSuccess: 99.6,
		Images:   []ImageVM{{Repo: "a/b", Tag: "v1", Identity: "ci", Passed: false, Crit: 1, High: 2}},
		PageMeta: PageMeta{Page: 1, PerPage: 10, Total: 1},
	}
	var buf bytes.Buffer
	if err := rnd.Render(&buf, "overview", vm); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"a/b", "80", "Overview", "99.6"} {
		if !strings.Contains(out, want) {
			t.Errorf("overview output missing %q", want)
		}
	}
}

func TestRenderOverviewDegraded(t *testing.T) {
	rnd, _ := NewRenderer()
	var buf bytes.Buffer
	if err := rnd.Render(&buf, "overview", OverviewVM{Range: Range1d, Errored: true}); err != nil {
		t.Fatalf("render degraded: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("degraded overview produced no output")
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
