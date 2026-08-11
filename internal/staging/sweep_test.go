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

// TestSweepScratchReclaimsPromoteRebuilds covers the dir the deferred-promotion path
// creates. When a sibling replica claims a job it re-assembles the layout into a
// merlin-promote-* dir; and because scratch is a per-pod emptyDir, the ORIGIN pod's
// merlin-assemble-* dir is then unreachable by any running code — its owner (the
// worker) is on the other pod and cleans up only what it created. Both must be
// sweepable or every cross-pod promotion leaks a layout permanently.
func TestSweepScratchReclaimsPromoteRebuilds(t *testing.T) {
	base := t.TempDir()
	mkAged(t, base, "merlin-promote-987654", 48*time.Hour)
	live := mkAged(t, base, "merlin-promote-live", time.Minute)

	n, err := SweepScratch(base, 24*time.Hour)
	if err != nil {
		t.Fatalf("SweepScratch: %v", err)
	}
	if n != 1 {
		t.Errorf("removed = %d, want 1", n)
	}
	// A young rebuild may belong to a promotion pushing right now; removing it would
	// fail that push and burn an attempt.
	if _, err := os.Stat(live); err != nil {
		t.Errorf("fresh promote rebuild was removed — would break a live promotion: %v", err)
	}
}

// TestScratchBytesMeasuresOnlyOurOwnDirs backs the disk gauge. Deferred promotion
// means scratch is held past the response, so "how full is the volume" became an
// operational question with no answer — the metric is what makes the pending bound
// tunable instead of guessed.
func TestScratchBytesMeasuresOnlyOurOwnDirs(t *testing.T) {
	base := t.TempDir()
	mkAged(t, base, "merlin-assemble-1", time.Minute) // 1 byte of payload
	mkAged(t, base, "merlin-promote-2", time.Minute)  // 1 byte of payload
	// Not ours. Counting other tenants of the mount would misreport Merlin's own
	// footprint, which is the number the pending bound is derived from.
	foreign := filepath.Join(base, "someone-elses-data")
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "big"), make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ScratchBytes(base)
	if err != nil {
		t.Fatalf("ScratchBytes: %v", err)
	}
	// Exactly the two payload bytes: file sizes only, so the result does not depend on
	// the filesystem's directory-entry overhead.
	if got != 2 {
		t.Errorf("ScratchBytes = %d, want 2 (one byte per scratch dir, foreign data excluded)", got)
	}
}

// TestScratchBytesMissingBaseIsZero keeps the metric from failing startup or the
// scrape when scratch_dir is unset or the mount does not exist yet.
func TestScratchBytesMissingBaseIsZero(t *testing.T) {
	for _, base := range []string{"", filepath.Join(t.TempDir(), "nope")} {
		got, err := ScratchBytes(base)
		if err != nil || got != 0 {
			t.Errorf("ScratchBytes(%q) = (%d, %v), want (0, nil)", base, got, err)
		}
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
