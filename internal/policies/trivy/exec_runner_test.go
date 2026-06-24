package trivy

import (
	"context"
	"strings"
	"testing"
)

func TestExecRunnerParsesOutput(t *testing.T) {
	er := &execRunner{
		binary: "trivy",
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "trivy" {
				t.Errorf("binary = %q, want trivy", name)
			}
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--format json") {
				t.Errorf("args missing --format json: %v", args)
			}
			return []byte(`{"SchemaVersion":2,"Metadata":{"DBVersion":"d1"},"Results":[]}`), nil
		},
	}
	rep, err := er.Scan(context.Background(), "/oci/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.DBVersion != "d1" {
		t.Errorf("DBVersion = %q, want d1", rep.DBVersion)
	}
}
