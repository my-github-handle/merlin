package staging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func newTestStore() *Store {
	n := 0
	return New(NewMemoryBlobStore(), NewMemorySessionStore(), func() string {
		n++
		return "upload-" + string(rune('0'+n))
	})
}

func TestCompleteBlobThenManifest(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	layer := []byte("layer-1")
	dg := digestOf(layer)

	up, err := s.BeginUpload(ctx, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteChunk(ctx, up, 0, bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	// Complete with empty final body; digest verifies the accumulated chunks
	if err := s.CompleteBlob(ctx, up, dg, bytes.NewReader(nil)); err != nil {
		t.Fatalf("complete blob: %v", err)
	}
	mr, err := s.PutManifest(ctx, "repo", "v1", []byte(`{"manifest":true}`), []string{dg})
	if err != nil {
		t.Fatalf("put manifest: %v", err)
	}
	if mr.Repo != "repo" || mr.Ref != "v1" {
		t.Errorf("manifest ref = %+v", mr)
	}
}

func TestPutManifestFailsWhenBlobMissing(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	_, err := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), []string{"sha256:missing"})
	if !errors.Is(err, ErrIncompletePush) {
		t.Errorf("expected ErrIncompletePush, got %v", err)
	}
}

func TestCompleteBlobRejectsBadDigest(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	up, _ := s.BeginUpload(ctx, "repo")
	// Stage some data via WriteChunk
	_, _ = s.WriteChunk(ctx, up, 0, bytes.NewReader([]byte("actual-data")))
	// Try to complete with a digest that doesn't match
	err := s.CompleteBlob(ctx, up, "sha256:deadbeef", bytes.NewReader(nil))
	if err == nil {
		t.Error("expected digest mismatch error")
	}
}

func TestWriteChunkOutOfOrder(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	up, _ := s.BeginUpload(ctx, "repo")
	if _, err := s.WriteChunk(ctx, up, 0, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatal(err)
	}
	// claim offset 0 again — stale, should be rejected
	_, err := s.WriteChunk(ctx, up, 0, bytes.NewReader([]byte("def")))
	if !errors.Is(err, ErrOutOfOrder) {
		t.Errorf("expected ErrOutOfOrder, got %v", err)
	}
}

func TestCompleteBlobVerifiesAccumulatedChunks(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	full := []byte("chunk-A-chunk-B")
	dg := digestOf(full)

	up, _ := s.BeginUpload(ctx, "repo")
	// Two chunks via WriteChunk, nothing in the final CompleteBlob reader.
	off, err := s.WriteChunk(ctx, up, 0, bytes.NewReader([]byte("chunk-A-")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteChunk(ctx, up, off, bytes.NewReader([]byte("chunk-B"))); err != nil {
		t.Fatal(err)
	}
	// Complete with empty final body; digest must verify the ACCUMULATED chunks.
	if err := s.CompleteBlob(ctx, up, dg, bytes.NewReader(nil)); err != nil {
		t.Fatalf("accumulated chunks should verify: %v", err)
	}
	mr, err := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), []string{dg})
	if err != nil {
		t.Fatalf("put manifest: %v", err)
	}
	if len(mr.LayerDigests) != 1 {
		t.Errorf("manifest layers = %v", mr.LayerDigests)
	}
}

func TestCompleteBlobRejectsWhenAccumulatedDigestWrong(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	up, _ := s.BeginUpload(ctx, "repo")
	_, _ = s.WriteChunk(ctx, up, 0, bytes.NewReader([]byte("actual-bytes")))
	// Claim a digest of different content -> must error.
	if err := s.CompleteBlob(ctx, up, digestOf([]byte("other")), bytes.NewReader(nil)); err == nil {
		t.Error("expected digest mismatch on accumulated data")
	}
}
