package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/merlin-gate/merlin/internal/staging"
)

func TestBlobUploadPOSTCreatesSession(t *testing.T) {
	store := staging.New(
		staging.NewMemoryBlobStore(),
		staging.NewMemorySessionStore(),
		func() string { return "test-upload-uuid" },
	)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("reg.example.com", nil, fakeAuth{ok: true}), Store: store})

	req := httptest.NewRequest(http.MethodPost, "/v2/myrepo/blobs/uploads/", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("POST: status = %d, want 202", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/v2/myrepo/blobs/uploads/test-upload-uuid") {
		t.Errorf("Location = %q, want to contain /v2/myrepo/blobs/uploads/test-upload-uuid", loc)
	}
	uuid := rec.Header().Get("Docker-Upload-UUID")
	if uuid != "test-upload-uuid" {
		t.Errorf("Docker-Upload-UUID = %q, want test-upload-uuid", uuid)
	}
	rng := rec.Header().Get("Range")
	if rng != "0-0" {
		t.Errorf("Range = %q, want 0-0", rng)
	}
}

func TestBlobUploadPATCHAppendsChunk(t *testing.T) {
	store := staging.New(
		staging.NewMemoryBlobStore(),
		staging.NewMemorySessionStore(),
		func() string { return "upload-1" },
	)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("reg.example.com", nil, fakeAuth{ok: true}), Store: store})

	// Begin upload
	uploadID, err := store.BeginUpload(nil, "myrepo")
	if err != nil {
		t.Fatalf("BeginUpload: %v", err)
	}

	chunk := []byte("hello world")
	req := httptest.NewRequest(http.MethodPatch, "/v2/myrepo/blobs/uploads/"+uploadID, bytes.NewReader(chunk))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Content-Range", "0-10")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("PATCH: status = %d, want 202", rec.Code)
	}
	if rec.Header().Get("Docker-Upload-UUID") != uploadID {
		t.Errorf("Docker-Upload-UUID = %q, want %q", rec.Header().Get("Docker-Upload-UUID"), uploadID)
	}
	// Range should be 0-10 (11 bytes written: offset 0..10 inclusive)
	rng := rec.Header().Get("Range")
	if rng != "0-10" {
		t.Errorf("Range = %q, want 0-10", rng)
	}
}

func TestBlobUploadPUTCompletesWithCorrectDigest(t *testing.T) {
	store := staging.New(
		staging.NewMemoryBlobStore(),
		staging.NewMemorySessionStore(),
		func() string { return "upload-2" },
	)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("reg.example.com", nil, fakeAuth{ok: true}), Store: store})

	// Begin upload
	uploadID, err := store.BeginUpload(nil, "myrepo")
	if err != nil {
		t.Fatalf("BeginUpload: %v", err)
	}

	// Write chunk
	chunk := []byte("layer data")
	if _, err := store.WriteChunk(nil, uploadID, 0, bytes.NewReader(chunk)); err != nil {
		t.Fatalf("WriteChunk: %v", err)
	}

	// Compute digest
	h2 := sha256.New()
	h2.Write(chunk)
	digest := fmt.Sprintf("sha256:%x", h2.Sum(nil))

	// Complete with PUT
	req := httptest.NewRequest(http.MethodPut, "/v2/myrepo/blobs/uploads/"+uploadID+"?digest="+digest, nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("PUT: status = %d, want 201", rec.Code)
	}
	if rec.Header().Get("Docker-Content-Digest") != digest {
		t.Errorf("Docker-Content-Digest = %q, want %q", rec.Header().Get("Docker-Content-Digest"), digest)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/v2/myrepo/blobs/"+digest) {
		t.Errorf("Location = %q, want to contain /v2/myrepo/blobs/%s", loc, digest)
	}
}

func TestBlobUploadPUTRejectsWrongDigest(t *testing.T) {
	store := staging.New(
		staging.NewMemoryBlobStore(),
		staging.NewMemorySessionStore(),
		func() string { return "upload-3" },
	)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("reg.example.com", nil, fakeAuth{ok: true}), Store: store})

	// Begin upload
	uploadID, err := store.BeginUpload(nil, "myrepo")
	if err != nil {
		t.Fatalf("BeginUpload: %v", err)
	}

	// Write chunk
	chunk := []byte("layer data")
	if _, err := store.WriteChunk(nil, uploadID, 0, bytes.NewReader(chunk)); err != nil {
		t.Fatalf("WriteChunk: %v", err)
	}

	// Wrong digest
	wrongDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	// Complete with PUT
	req := httptest.NewRequest(http.MethodPut, "/v2/myrepo/blobs/uploads/"+uploadID+"?digest="+wrongDigest, nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("PUT with wrong digest: status = %d, want 400", rec.Code)
	}
}

func TestBlobUploadPATCHRejectsOutOfOrderChunk(t *testing.T) {
	store := staging.New(
		staging.NewMemoryBlobStore(),
		staging.NewMemorySessionStore(),
		func() string { return "upload-4" },
	)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("reg.example.com", nil, fakeAuth{ok: true}), Store: store})

	// Begin upload
	uploadID, err := store.BeginUpload(nil, "myrepo")
	if err != nil {
		t.Fatalf("BeginUpload: %v", err)
	}

	// Try to PATCH at offset 10 without writing 0-9 first
	chunk := []byte("data")
	req := httptest.NewRequest(http.MethodPatch, "/v2/myrepo/blobs/uploads/"+uploadID, bytes.NewReader(chunk))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Content-Range", "10-13")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("PATCH out-of-order: status = %d, want 416", rec.Code)
	}
}

func TestBlobUploadFullSequence(t *testing.T) {
	store := staging.New(
		staging.NewMemoryBlobStore(),
		staging.NewMemorySessionStore(),
		func() string { return "upload-full" },
	)
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("reg.example.com", nil, fakeAuth{ok: true}), Store: store})

	// POST to begin
	req := httptest.NewRequest(http.MethodPost, "/v2/testapp/blobs/uploads/", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST: status = %d, want 202", rec.Code)
	}
	uploadID := rec.Header().Get("Docker-Upload-UUID")
	if uploadID == "" {
		t.Fatal("POST: missing Docker-Upload-UUID")
	}

	// PATCH a chunk
	chunk1 := []byte("first part")
	req = httptest.NewRequest(http.MethodPatch, "/v2/testapp/blobs/uploads/"+uploadID, bytes.NewReader(chunk1))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Content-Range", fmt.Sprintf("0-%d", len(chunk1)-1))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("PATCH: status = %d, want 202", rec.Code)
	}

	// PATCH another chunk
	chunk2 := []byte(" second part")
	req = httptest.NewRequest(http.MethodPatch, "/v2/testapp/blobs/uploads/"+uploadID, bytes.NewReader(chunk2))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	offset := len(chunk1)
	req.Header.Set("Content-Range", fmt.Sprintf("%d-%d", offset, offset+len(chunk2)-1))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("PATCH 2: status = %d, want 202", rec.Code)
	}

	// Compute digest of full content
	fullContent := append(chunk1, chunk2...)
	h2 := sha256.New()
	h2.Write(fullContent)
	digest := fmt.Sprintf("sha256:%x", h2.Sum(nil))

	// PUT to complete
	req = httptest.NewRequest(http.MethodPut, "/v2/testapp/blobs/uploads/"+uploadID+"?digest="+digest, nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want 201", rec.Code)
	}
	if rec.Header().Get("Docker-Content-Digest") != digest {
		t.Errorf("Docker-Content-Digest = %q, want %q", rec.Header().Get("Docker-Content-Digest"), digest)
	}

	// The blob is now stored and marked complete in staging.
	// We trust CompleteBlob worked since it returned 201 without error.
}

// clearSpy wraps a SessionStore and records which uploads were Cleared, so a test
// can assert the handler retires session state on its failure paths instead of
// stranding it (each stranded session is a Valkey key with no owner).
type clearSpy struct {
	staging.SessionStore
	mu      sync.Mutex
	cleared []string
}

func newClearSpy() *clearSpy {
	return &clearSpy{SessionStore: staging.NewMemorySessionStore()}
}

func (c *clearSpy) Clear(ctx context.Context, uploadID string) error {
	c.mu.Lock()
	c.cleared = append(c.cleared, uploadID)
	c.mu.Unlock()
	return c.SessionStore.Clear(ctx, uploadID)
}

func (c *clearSpy) clearedUploads() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.cleared...)
}

// TestUploadFailurePathsAbandonSession pins the handler wiring for the staging leak.
// A push that cannot proceed must retire its upload session; otherwise the offset key
// survives with no owner. The digest-mismatch paths are the important ones: the
// digest is final, so the client can never resume — it must start a fresh upload.
func TestUploadFailurePathsAbandonSession(t *testing.T) {
	goodBody := []byte("layer data")
	sum := sha256.Sum256(goodBody)
	goodDigest := "sha256:" + hex.EncodeToString(sum[:])
	badDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name     string
		uploadID string
		// do drives the request(s); it returns the upload ID whose session must be gone.
		do       func(t *testing.T, h *Handler, st *staging.Store) string
		wantCode int
	}{
		{
			name:     "monolithic POST with wrong digest",
			uploadID: "u-mono-bad",
			do: func(t *testing.T, h *Handler, st *staging.Store) string {
				// The client never learns this upload ID, so nothing can ever clean it up.
				req := httptest.NewRequest(http.MethodPost, "/v2/app/blobs/uploads/?digest="+badDigest, bytes.NewReader(goodBody))
				req.Host = testTenantHost
				req.Header.Set("Authorization", "Bearer good")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400", rec.Code)
				}
				return "u-mono-bad"
			},
		},
		{
			name:     "PUT with wrong digest",
			uploadID: "u-put-bad",
			do: func(t *testing.T, h *Handler, st *staging.Store) string {
				up, err := st.BeginUpload(context.Background(), "app")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := st.WriteChunk(context.Background(), up, 0, bytes.NewReader(goodBody)); err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPut, "/v2/app/blobs/uploads/"+up+"?digest="+badDigest, nil)
				req.Host = testTenantHost
				req.Header.Set("Authorization", "Bearer good")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400", rec.Code)
				}
				return up
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spy := newClearSpy()
			st := staging.New(staging.NewMemoryBlobStore(), spy, func() string { return tc.uploadID })
			h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), Store: st})

			up := tc.do(t, h, st)

			var found bool
			for _, c := range spy.clearedUploads() {
				if c == up {
					found = true
				}
			}
			if !found {
				t.Errorf("upload %q session was not cleared (cleared=%v); it would leak a Valkey offset key", up, spy.clearedUploads())
			}
		})
	}

	// Sanity: the happy path must still clear its session too, and must not regress.
	t.Run("successful PUT clears session", func(t *testing.T) {
		spy := newClearSpy()
		st := staging.New(staging.NewMemoryBlobStore(), spy, func() string { return "u-ok" })
		h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), Store: st})

		up, err := st.BeginUpload(context.Background(), "app")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.WriteChunk(context.Background(), up, 0, bytes.NewReader(goodBody)); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPut, "/v2/app/blobs/uploads/"+up+"?digest="+goodDigest, nil)
		req.Host = testTenantHost
		req.Header.Set("Authorization", "Bearer good")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
		if len(spy.clearedUploads()) == 0 {
			t.Error("successful PUT left the upload session behind")
		}
	})
}

func TestMonolithicPostUploadPersistsBlob(t *testing.T) {
	st := staging.New(staging.NewMemoryBlobStore(), staging.NewMemorySessionStore(), func() string { return "u-mono" })
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), Store: st})
	body := []byte("monolithic-blob-bytes")
	sum := sha256.Sum256(body)
	dg := "sha256:" + hex.EncodeToString(sum[:])

	// monolithic upload: POST .../uploads/?digest=<dg> with the full body
	req := httptest.NewRequest(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg, bytes.NewReader(body))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("monolithic POST: code = %d, want 201", rec.Code)
	}
	if rec.Header().Get("Docker-Content-Digest") != dg {
		t.Errorf("Docker-Content-Digest = %q, want %q", rec.Header().Get("Docker-Content-Digest"), dg)
	}
	// the blob must now be complete so a manifest referencing it assembles
	if _, err := st.PutManifest(context.Background(), "app", "v1", []byte(`{}`), "", []string{dg}); err != nil {
		t.Errorf("blob not persisted by monolithic POST: PutManifest err = %v", err)
	}
}
