package staging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// terminaler is what internal/promote matches on. Asserting through this local
// interface rather than through *BlobMissingError directly is deliberate: the method
// set is the contract another package depends on, so a rename or a signature change
// here must fail a test in THIS package, where the type lives.
type terminaler interface{ Terminal() bool }

// TestBlobMissingErrorIsTerminal pins the classification itself. A blob-store 404
// means the bytes were deleted (a Cleanup released the last ref-count) or never
// written; either way every retry re-reads the same absent key. The promotion worker
// retires immediately on this, so answering false here would restore the three
// identical failed attempts — and the three contradictory audit rows — that this type
// exists to end.
func TestBlobMissingErrorIsTerminal(t *testing.T) {
	var err error = &BlobMissingError{Key: "blob/sha256:abc"}

	var t2 terminaler
	if !errors.As(err, &t2) {
		t.Fatal("BlobMissingError does not satisfy the Terminal() contract promote matches on")
	}
	if !t2.Terminal() {
		t.Error("Terminal() = false; a missing blob cannot appear on retry")
	}
	// The key must be in the message: with several blobs per image, "not found" alone
	// does not say which layer went missing, and that digest is the only handle on
	// whether it was shared with another push.
	if got := err.Error(); !strings.Contains(got, "blob/sha256:abc") {
		t.Errorf("Error() = %q, want it to name the key", got)
	}
}

// TestBlobMissingErrorSurvivesWrapping is the case that makes the design work at all.
// The error is raised deep in fetchVerified and reaches the worker through two layers
// of fmt.Errorf("%w") — assemble's "get blob %s" and localize's "re-assemble %s". If
// the classification did not survive that, the worker would see an opaque string and
// spend the full retry budget.
func TestBlobMissingErrorSurvivesWrapping(t *testing.T) {
	wrapped := errors.New("outer: " + (&BlobMissingError{Key: "k"}).Error())
	var t2 terminaler
	if errors.As(wrapped, &t2) {
		t.Fatal("a string-formatted error must NOT be classified; only %w wrapping preserves it")
	}

	// The real chain, spelled the way assemble.go and worker.go spell it.
	inner := fmt.Errorf("get blob sha256:abc: %w", &BlobMissingError{Key: "blob/sha256:abc"})
	deep := fmt.Errorf("re-assemble app:v1: %w", inner)
	if !errors.As(deep, &t2) {
		t.Fatal("Terminal classification lost through two layers of %w wrapping")
	}
	if !t2.Terminal() {
		t.Error("Terminal() = false after wrapping")
	}
}

// TestMemoryBlobStoreReportsMissingAsTerminal keeps the test double honest. Every
// hermetic test of the assemble path runs against this store, so if it returned a
// plain error while Azure returned a terminal one, the classification would be
// untested everywhere it is actually used.
func TestMemoryBlobStoreReportsMissingAsTerminal(t *testing.T) {
	_, err := NewMemoryBlobStore().Get(context.Background(), "blob/sha256:missing")
	if err == nil {
		t.Fatal("Get on an absent key succeeded")
	}
	var t2 terminaler
	if !errors.As(err, &t2) || !t2.Terminal() {
		t.Errorf("Get error = %v (%T), want a terminal *BlobMissingError", err, err)
	}
}

// TestAzureGetMapsBlobNotFoundToTerminal covers the mapping for the store that
// actually runs in production, where the 404 arrives as an *azcore.ResponseError
// carrying x-ms-error-code: BlobNotFound. Before this mapping, azureBlobStore.Get
// returned that error verbatim and nothing downstream could tell a deleted blob from
// a network blip — so both got three attempts.
func TestAzureGetMapsBlobNotFoundToTerminal(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantTerminal bool
	}{
		{
			name:         "blob not found",
			err:          &azcore.ResponseError{ErrorCode: "BlobNotFound", StatusCode: http.StatusNotFound},
			wantTerminal: true,
		},
		{
			// A 404 whose code says the CONTAINER is gone is configuration, not a
			// missing layer. It is deliberately not mapped: calling it a missing blob
			// would send the reader hunting for a digest that was never the problem.
			name:         "container not found",
			err:          &azcore.ResponseError{ErrorCode: "ContainerNotFound", StatusCode: http.StatusNotFound},
			wantTerminal: false,
		},
		{
			// The case the retry budget exists for. Classifying this as terminal would
			// abandon an approved image on a transient blip.
			name:         "server busy",
			err:          &azcore.ResponseError{ErrorCode: "ServerBusy", StatusCode: http.StatusServiceUnavailable},
			wantTerminal: false,
		},
		{
			name:         "plain transport error",
			err:          errors.New("dial tcp: connection refused"),
			wantTerminal: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBlobGetError("blob/sha256:abc", tc.err)
			var t2 terminaler
			terminal := errors.As(got, &t2) && t2.Terminal()
			if terminal != tc.wantTerminal {
				t.Errorf("terminal = %v, want %v (error %v)", terminal, tc.wantTerminal, got)
			}
			if !tc.wantTerminal && !errors.Is(got, tc.err) {
				t.Errorf("unmapped error was replaced: got %v, want the original preserved", got)
			}
		})
	}
}

// TestAssembleReportsADeletedBlobAsTerminal is the end-to-end case, and it is the
// production incident in miniature: a push's blob ref-count is released by Cleanup,
// the bytes are deleted, and a promotion job then tries to re-assemble the image on
// another pod. That is the exact sequence that produced 160 `get blob sha256:...: 404
// BlobNotFound` audit rows in a day.
//
// The assertion is not "Assemble fails" — it always did — but that the failure
// arrives classified, because that is what stops internal/promote from retrying it
// twice more and writing two more contradictory rows.
func TestAssembleReportsADeletedBlobAsTerminal(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	layer := makeLayerTar(t, "rhel")
	dgst := digestOf(layer)

	up, _ := s.BeginUpload(ctx, "repo")
	if err := s.CompleteBlob(ctx, up, dgst, bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	mr, err := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), "", []string{dgst})
	if err != nil {
		t.Fatal(err)
	}
	// The winning duplicate cleaned up: last ref released, bytes deleted.
	if err := s.Cleanup(ctx, mr, t.TempDir()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	_, err = s.Assemble(ctx, mr, t.TempDir())
	if err == nil {
		t.Fatal("Assemble succeeded after the blob was deleted")
	}
	var t2 terminaler
	if !errors.As(err, &t2) || !t2.Terminal() {
		t.Errorf("Assemble error = %v (%T), want terminal so promote retires instead of retrying", err, err)
	}
	if !strings.Contains(err.Error(), dgst) {
		t.Errorf("Assemble error = %q, want it to name the missing digest", err)
	}
}
