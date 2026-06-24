package baseimage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

func stageWithOSRelease(t *testing.T, contents string) policy.StagedImage {
	t.Helper()
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if contents != "" {
		if err := os.WriteFile(filepath.Join(etc, "os-release"), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return policy.StagedImage{FSPath: root}
}

func TestBaseImageAllowsUBI(t *testing.T) {
	p := New([]string{"rhel", "wolfi", "chainguard"})
	img := stageWithOSRelease(t, `ID="rhel"`+"\n")
	v, err := p.Evaluate(context.Background(), img)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed {
		t.Errorf("UBI should pass, reasons=%v", v.Reasons)
	}
}

func TestBaseImageAllowsWolfi(t *testing.T) {
	p := New([]string{"rhel", "wolfi", "chainguard"})
	img := stageWithOSRelease(t, "ID=wolfi\n")
	v, _ := p.Evaluate(context.Background(), img)
	if !v.Passed {
		t.Errorf("Wolfi should pass, reasons=%v", v.Reasons)
	}
}

func TestBaseImageRejectsAlpine(t *testing.T) {
	p := New([]string{"rhel", "wolfi", "chainguard"})
	img := stageWithOSRelease(t, "ID=alpine\n")
	v, _ := p.Evaluate(context.Background(), img)
	if v.Passed {
		t.Error("alpine should be rejected")
	}
	if len(v.Reasons) == 0 {
		t.Error("rejection should include a reason")
	}
}

func TestBaseImageRejectsMissingOSRelease(t *testing.T) {
	p := New([]string{"rhel"})
	img := stageWithOSRelease(t, "") // no file written
	v, err := p.Evaluate(context.Background(), img)
	if err != nil {
		t.Fatalf("missing os-release must be a fail, not an error: %v", err)
	}
	if v.Passed {
		t.Error("missing os-release should be rejected")
	}
}
