package staging

import (
	"context"
	"testing"
)

// TestDecBlobRefMissingCounterIsError pins the invariant documented in
// Cleanup (assemble.go): when the reference count is UNKNOWN, the blob must be
// leaked, never deleted — a leak is reclaimable, a wrongly deleted shared layer is a
// broken push.
//
// An absent counter means unknown, not zero. Redis/Valkey DECR on a missing key
// returns -1, which Cleanup's "remaining <= 0" test would read as "no references
// left" and delete the bytes. Reporting an error instead routes Cleanup into its
// existing err != nil branch, which leaks by design. This matters because the ref
// key now carries a TTL, giving the counter a second way to disappear.
func TestDecBlobRefMissingCounterIsError(t *testing.T) {
	ss := NewMemorySessionStore()
	ctx := context.Background()

	if _, err := ss.DecBlobRef(ctx, "sha256:never-incremented"); err == nil {
		t.Error("DecBlobRef on absent counter returned nil error; Cleanup would delete a blob whose ref count is unknown")
	}
}

// TestDecBlobRefToZeroDeletesCounter covers the normal path: the last referencing
// push drives the count to zero, which authorizes deleting the blob bytes.
func TestDecBlobRefToZeroDeletesCounter(t *testing.T) {
	ss := NewMemorySessionStore()
	ctx := context.Background()
	const dg = "sha256:one-ref"

	if _, err := ss.IncBlobRef(ctx, dg); err != nil {
		t.Fatal(err)
	}
	n, err := ss.DecBlobRef(ctx, dg)
	if err != nil {
		t.Fatalf("DecBlobRef: %v", err)
	}
	if n != 0 {
		t.Errorf("remaining = %d, want 0", n)
	}
	// Counter is now gone, so a further decrement is an unknown count, not -1.
	if _, err := ss.DecBlobRef(ctx, dg); err == nil {
		t.Error("second DecBlobRef returned nil error; count is unknown and the blob must be leaked, not deleted")
	}
}

// TestDecBlobRefSharedBlobKeepsBytes covers the concurrent-push case the ref count
// exists for: two pushes share a layer, so the first to finish must NOT authorize
// deleting bytes the second still needs.
func TestDecBlobRefSharedBlobKeepsBytes(t *testing.T) {
	ss := NewMemorySessionStore()
	ctx := context.Background()
	const dg = "sha256:shared-base-layer"

	for i := 0; i < 2; i++ {
		if _, err := ss.IncBlobRef(ctx, dg); err != nil {
			t.Fatal(err)
		}
	}
	n, err := ss.DecBlobRef(ctx, dg)
	if err != nil {
		t.Fatalf("DecBlobRef: %v", err)
	}
	if n != 1 {
		t.Errorf("remaining = %d, want 1 (the concurrent push still holds a reference)", n)
	}
}
