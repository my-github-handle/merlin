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

// stageWithUsrLibOSRelease writes os-release ONLY at /usr/lib/os-release with no
// /etc/os-release. This mirrors a real UBI image: /etc/os-release is a symlink to
// ../usr/lib/os-release, and Merlin's tar extraction skips symlinks, so only the
// /usr/lib copy lands in the assembled rootfs.
func stageWithUsrLibOSRelease(t *testing.T, contents string) policy.StagedImage {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "usr", "lib")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "os-release"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return policy.StagedImage{FSPath: root}
}

func TestBaseImageFallsBackToUsrLibOSRelease(t *testing.T) {
	p := New([]string{"rhel", "wolfi", "chainguard"})
	img := stageWithUsrLibOSRelease(t, `ID="rhel"`+"\n")
	v, err := p.Evaluate(context.Background(), img)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed {
		t.Errorf("UBI with only /usr/lib/os-release should pass, reasons=%v", v.Reasons)
	}
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

func TestBaseImageRejectsEmptyID(t *testing.T) {
	p := New([]string{"rhel", "wolfi", "chainguard"})
	img := stageWithOSRelease(t, "ID=\n") // file present, but ID empty
	v, err := p.Evaluate(context.Background(), img)
	if err != nil {
		t.Fatalf("empty ID must be a fail, not an error: %v", err)
	}
	if v.Passed {
		t.Error("empty ID should be rejected")
	}
}

func TestBaseImageAllowsChainguard(t *testing.T) {
	p := New([]string{"rhel", "wolfi", "chainguard"})
	img := stageWithOSRelease(t, "ID=chainguard\n")
	v, err := p.Evaluate(context.Background(), img)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed {
		t.Errorf("chainguard should pass, reasons=%v", v.Reasons)
	}
}

func TestBaseImageMatchesCaseInsensitively(t *testing.T) {
	p := New([]string{"rhel", "wolfi", "chainguard"})
	img := stageWithOSRelease(t, `ID="RHEL"`+"\n") // uppercase in the image
	v, err := p.Evaluate(context.Background(), img)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed {
		t.Errorf("RHEL (uppercase) should pass via case-insensitive match, reasons=%v", v.Reasons)
	}
}
