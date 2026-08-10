package staging

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mkAged creates a directory (with a file inside, so removal must be recursive) and
// backdates its mtime by age.
func mkAged(t *testing.T, base, name string, age time.Duration) string {
	t.Helper()
	dir := filepath.Join(base, name)
	if err := os.MkdirAll(filepath.Join(dir, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inner", "blob"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Backdate. The reference time is taken from the fixture itself so the test does
	// not depend on wall-clock alignment.
	mt := time.Now().Add(-age)
	if err := os.Chtimes(dir, mt, mt); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestSweepScratchRemovesStaleDirs pins the fix for the scratch-dir leak. Assembly
// cleanup is deferred, and a SIGKILL (the pods were OOMKilled, exit 137) skips every
// defer — leaving 15.7G of merlin-assemble-*/stereoscope-*/getter* dirs stranded in
// the scratch mount, which no running code would ever reclaim.
func TestSweepScratchRemovesStaleDirs(t *testing.T) {
	base := t.TempDir()

	stale := []string{
		"merlin-assemble-123456",
		"stereoscope-1234567890",
		"getter1234567890",
	}
	for _, n := range stale {
		mkAged(t, base, n, 48*time.Hour)
	}
	// A dir that is ours but still YOUNG: it may belong to an assembly running right
	// now in this process, and deleting it would break a live push mid-scan.
	fresh := mkAged(t, base, "merlin-assemble-fresh", time.Minute)
	// A dir that is NOT ours: the sweep must never touch unrelated files in the mount.
	foreign := mkAged(t, base, "someone-elses-data", 48*time.Hour)

	n, err := SweepScratch(base, 24*time.Hour)
	if err != nil {
		t.Fatalf("SweepScratch: %v", err)
	}
	if n != len(stale) {
		t.Errorf("removed = %d, want %d", n, len(stale))
	}
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(base, name)); !os.IsNotExist(err) {
			t.Errorf("stale dir %s still present", name)
		}
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh scratch dir was removed — would break a live push: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign dir was removed — sweep must only match its own prefixes: %v", err)
	}
}

// TestSweepScratchEmptyBaseIsNoop guards the default config: scratch_dir may be
// unset, in which case there is no directory to sweep and startup must not fail.
func TestSweepScratchEmptyBaseIsNoop(t *testing.T) {
	n, err := SweepScratch("", time.Hour)
	if err != nil || n != 0 {
		t.Errorf("SweepScratch(\"\") = (%d, %v), want (0, nil)", n, err)
	}
}

// TestSweepScratchMissingBaseIsNoop covers a configured-but-not-yet-created mount:
// a missing dir is nothing to reclaim, not a startup failure.
func TestSweepScratchMissingBaseIsNoop(t *testing.T) {
	n, err := SweepScratch(filepath.Join(t.TempDir(), "nope"), time.Hour)
	if err != nil || n != 0 {
		t.Errorf("SweepScratch(missing) = (%d, %v), want (0, nil)", n, err)
	}
}

// TestSweepScratchIgnoresFiles ensures a stray FILE with a matching prefix is left
// alone; the sweep's contract is scratch directories, and removing arbitrary files
// would widen its blast radius.
func TestSweepScratchIgnoresFiles(t *testing.T) {
	base := t.TempDir()
	f := filepath.Join(base, "merlin-assemble-notadir")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(f, mt, mt); err != nil {
		t.Fatal(err)
	}

	n, err := SweepScratch(base, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("removed = %d, want 0", n)
	}
	if _, err := os.Stat(f); err != nil {
		t.Errorf("matching FILE was removed: %v", err)
	}
}
