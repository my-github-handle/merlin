package staging

import "fmt"

// BlobMissingError reports that a staged blob's bytes are gone from the blob store.
//
// It is a distinct type rather than a sentinel because callers need to ask one
// question of it — "can a retry ever succeed?" — and the answer is no. A blob store
// 404 is not weather. The bytes were deleted (a Cleanup released the last ref-count)
// or were never written, and neither heals on its own; every retry re-reads the same
// absent key, fails identically, and adds a duplicate audit row.
//
// That is not hypothetical either. Promotions that hit this burned their whole
// attempt budget on three identical 404s each, and the retries were what turned one
// stolen claim into six contradictory audit rows for a single push. See
// internal/promote's Worker.fail, which retires on Terminal() instead of retrying.
//
// A sentinel error value could not carry Terminal(), and an errors.Is check against
// one would have to be written out at every call site; a method travels with the
// error through fmt.Errorf("%w") wrapping.
type BlobMissingError struct {
	// Key is the blob-store key, not the digest: it is what was actually looked up,
	// and the prefix distinguishes a missing content blob from a missing manifest.
	Key string
}

func (e *BlobMissingError) Error() string {
	return fmt.Sprintf("blob %q not found in staging store", e.Key)
}

// Terminal reports that no retry of this operation can succeed. It is matched
// structurally (errors.As against an interface) by packages that must not import
// staging, so its name and signature are part of staging's API even though nothing
// here calls it.
func (e *BlobMissingError) Terminal() bool { return true }
