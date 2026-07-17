package grype

import (
	"context"
	"strings"
	"testing"
)

func TestExecRunnerBuildsGrypeCommand(t *testing.T) {
	er := &execRunner{
		binary: "grype",
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "grype" {
				t.Errorf("binary = %q, want grype", name)
			}
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "-o json") {
				t.Errorf("args missing -o json: %v", args)
			}
			if !strings.Contains(joined, "/oci/path") {
				t.Errorf("args missing oci path: %v", args)
			}
			// --by-cve normalizes advisory IDs (GO-/GHSA-) to their canonical
			// CVE when a mapping exists, matching the c3securitytools grype
			// import pipeline so stored cve_id values are consistent.
			if !strings.Contains(joined, "--by-cve") {
				t.Errorf("args missing --by-cve: %v", args)
			}
			return []byte(`{"matches":[],"descriptor":{"db":{"schemaVersion":5,"built":"2026-07-16T00:00:00Z"}}}`), nil
		},
	}
	rep, err := er.Scan(context.Background(), "/oci/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.DBVersion == "" {
		t.Errorf("DBVersion should be populated, got empty")
	}
}
