package staging

import (
	"bytes"
	"context"
	"testing"
)

// sessionCount reports how many upload sessions the in-memory store still holds.
// A finished or abandoned upload must leave none: every live session is an offset
// key that, in the Valkey-backed store, has no TTL and would leak forever.
func sessionCount(ss SessionStore) int {
	m, ok := ss.(*memSessionStore)
	if !ok {
		return -1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// TestCompleteBlobClearsUploadSession pins the fix for the upload-state leak.
// CompleteBlob deletes the temporary upload BLOB but historically never cleared
// the upload SESSION, so each push left a permanent "merlin:upload:<id>:offset"
// key in Valkey (observed live: 4851 keys, all TTL=-1, under maxmemory_policy
// noeviction).
func TestCompleteBlobClearsUploadSession(t *testing.T) {
	ss := NewMemorySessionStore()
	s := New(NewMemoryBlobStore(), ss, func() string { return "upload-1" })
	ctx := context.Background()

	layer := []byte("layer-1")
	dg := digestOf(layer)

	up, err := s.BeginUpload(ctx, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if got := sessionCount(ss); got != 1 {
		t.Fatalf("after BeginUpload: session count = %d, want 1", got)
	}
	if _, err := s.WriteChunk(ctx, up, 0, bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteBlob(ctx, up, dg, bytes.NewReader(nil)); err != nil {
		t.Fatalf("complete blob: %v", err)
	}

	if got := sessionCount(ss); got != 0 {
		t.Errorf("after CompleteBlob: session count = %d, want 0 (upload session leaked)", got)
	}
}

// TestAbandonUploadClearsSession pins the fix for the dominant leak shape seen in
// production: a client uploads blobs and then never sends the manifest, so the
// push is abandoned mid-flight. Without an explicit abandon path the session key
// survives forever.
func TestAbandonUploadClearsSession(t *testing.T) {
	ss := NewMemorySessionStore()
	s := New(NewMemoryBlobStore(), ss, func() string { return "upload-1" })
	ctx := context.Background()

	up, err := s.BeginUpload(ctx, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteChunk(ctx, up, 0, bytes.NewReader([]byte("partial"))); err != nil {
		t.Fatal(err)
	}

	if err := s.AbandonUpload(ctx, up); err != nil {
		t.Fatalf("abandon upload: %v", err)
	}
	if got := sessionCount(ss); got != 0 {
		t.Errorf("after AbandonUpload: session count = %d, want 0", got)
	}
	// The partially staged upload bytes must go too, or the blob store leaks.
	if _, err := s.blobs.Get(ctx, uploadKey(up)); err == nil {
		t.Error("after AbandonUpload: partial upload blob still present")
	}
}
