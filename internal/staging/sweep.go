package staging

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// scratchPrefixes are the directory-name prefixes Merlin's image assembly creates
// under the scratch base. "merlin-assemble-*" is ours directly (os.MkdirTemp);
// "stereoscope-*" and "getter*" are created by Syft/Grype beneath it and are left
// behind by the same crashes. "merlin-promote-*" is a layout rebuilt by the promotion
// worker when a sibling replica assembled the image (scratch is a per-pod emptyDir),
// which also strands the ORIGIN pod's merlin-assemble-* dir — no running code can
// reach it, because its owner is on the other pod. Anything not matching one of these
// is somebody else's data and is never touched.
var scratchPrefixes = []string{"merlin-assemble-", "merlin-promote-", "stereoscope-", "getter"}

// DefaultScratchMaxAge is the age past which a scratch directory is presumed
// abandoned. It must exceed the longest possible gate (scan timeout defaults to 5
// minutes) by a wide margin, since removing a live assembly's scratch dir would
// break that push mid-scan.
const DefaultScratchMaxAge = 24 * time.Hour

// SweepScratch removes abandoned scratch directories under base that are older than
// maxAge, returning how many it removed.
//
// Assembly cleans up its scratch dir with a defer, which covers every path EXCEPT
// the one that actually stranded 15.7G in production: SIGKILL. An OOM kill (exit
// 137) runs no deferred function, so the dir survives with no reference to it
// anywhere — no running code will ever reclaim it. Callers run this at startup,
// which is exactly when a crash's leftovers exist and no assembly is yet in flight.
//
// Safety comes from two conditions, both required:
//   - the name matches a scratchPrefixes entry (never unrelated files in the mount)
//   - the entry is a directory older than maxAge (never a live assembly's dir)
//
// An empty or missing base is a no-op, not an error: scratch_dir is optional and the
// mount may not exist yet. Per-entry removal failures are logged and skipped rather
// than aborting the sweep — reclaiming most of the space beats reclaiming none, and
// this must never prevent startup.
func SweepScratch(base string, maxAge time.Duration) (int, error) {
	if base == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read scratch dir %s: %w", base, err)
	}

	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for _, e := range entries {
		if !e.IsDir() || !hasScratchPrefix(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // vanished between ReadDir and Info; nothing to reclaim
		}
		if !info.ModTime().Before(cutoff) {
			continue // young enough that a live assembly may own it
		}
		path := filepath.Join(base, e.Name())
		if err := os.RemoveAll(path); err != nil {
			log.Printf("sweep scratch: remove %s: %v", path, err)
			continue
		}
		removed++
	}
	return removed, nil
}

// ScratchBytes totals the bytes Merlin's own scratch directories hold under base.
//
// Deferred promotion made this an operational question with no answer: a pending job
// keeps its OCI layout AND its extracted rootfs on the scratch volume long after the
// client got its 201, so the volume's occupancy no longer tracks in-flight requests.
// It is the number the pending-promotion bound is derived from, which is why only
// Merlin's own prefixes count — including another tenant of the mount would misreport
// Merlin's footprint.
//
// An empty or missing base is zero, not an error: scratch_dir is optional, the mount
// may not exist yet, and a metric must never fail a scrape. Per-entry walk errors are
// skipped for the same reason — a dir being removed underneath the walk (by the sweep,
// or by a finishing push) is normal, not a fault.
func ScratchBytes(base string) (int64, error) {
	if base == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read scratch dir %s: %w", base, err)
	}

	var total int64
	for _, e := range entries {
		if !e.IsDir() || !hasScratchPrefix(e.Name()) {
			continue
		}
		filepath.WalkDir(filepath.Join(base, e.Name()), func(_ string, d os.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return nil //nolint:nilerr // a vanishing entry is normal; keep walking
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			total += info.Size()
			return nil
		})
	}
	return total, nil
}

func hasScratchPrefix(name string) bool {
	for _, p := range scratchPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
