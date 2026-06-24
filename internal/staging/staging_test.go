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
	if err := s.CompleteBlob(ctx, up, dg, bytes.NewReader(layer)); err != nil {
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
	err := s.CompleteBlob(ctx, up, "sha256:deadbeef", bytes.NewReader([]byte("x")))
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
