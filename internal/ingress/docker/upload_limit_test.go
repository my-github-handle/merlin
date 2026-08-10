package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/staging"
)

// blockingBlobStore wraps a BlobStore and blocks inside Put until released, so a
// test can hold uploads mid-flight and observe how many run concurrently.
type blockingBlobStore struct {
	staging.BlobStore
	entered chan struct{}
	release chan struct{}

	mu       sync.Mutex
	inFlight int
	maxSeen  int
}

func newBlockingBlobStore(bufferedEntries int) *blockingBlobStore {
	return &blockingBlobStore{
		BlobStore: staging.NewMemoryBlobStore(),
		entered:   make(chan struct{}, bufferedEntries),
		release:   make(chan struct{}),
	}
}

func (b *blockingBlobStore) Put(ctx context.Context, key string, r io.Reader) error {
	b.mu.Lock()
	b.inFlight++
	if b.inFlight > b.maxSeen {
		b.maxSeen = b.inFlight
	}
	b.mu.Unlock()

	b.entered <- struct{}{}
	<-b.release

	b.mu.Lock()
	b.inFlight--
	b.mu.Unlock()
	return b.BlobStore.Put(ctx, key, r)
}

func (b *blockingBlobStore) peakConcurrency() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxSeen
}

// monolithicPush POSTs a whole blob in one request (the docker/buildkit monolithic
// upload form), which is the shortest path from an HTTP request to BlobStore.Put.
func monolithicPush(h *Handler, body []byte) *httptest.ResponseRecorder {
	sum := sha256.Sum256(body)
	dg := "sha256:" + hex.EncodeToString(sum[:])
	req := httptest.NewRequest(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg, bytes.NewReader(body))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// countingIDGen hands out unique upload IDs safely from concurrent handlers.
func countingIDGen() func() string {
	var mu sync.Mutex
	var n int
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		n++
		return fmt.Sprintf("u%d", n)
	}
}

// TestUploadConcurrencyIsBounded pins the memory ceiling on the upload path.
//
// WriteChunk/CompleteBlob read-modify-write the WHOLE accumulated upload
// (staging.go), so each in-flight upload holds a multiple of the blob size in
// memory. Only the manifest gate acquires the scan pool, so before this change
// concurrent uploads were unbounded: a handful of parallel pushes could walk the
// pod past its memory limit, which is how merlin was OOMKilled (exit 137) even
// with a 10Gi limit.
func TestUploadConcurrencyIsBounded(t *testing.T) {
	const limit = 2
	const callers = 6

	bs := newBlockingBlobStore(callers)
	st := staging.New(bs, staging.NewMemorySessionStore(), countingIDGen())
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), st, nil, nil, nil)
	h.SetUploadConcurrency(limit)

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			monolithicPush(h, []byte(fmt.Sprintf("blob-%d", i)))
		}(i)
	}

	// Saturate the limit...
	for i := 0; i < limit; i++ {
		select {
		case <-bs.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for uploads to reach the blob store")
		}
	}
	// ...then confirm nothing else gets through while the slots are held.
	select {
	case <-bs.entered:
		t.Errorf("more than %d uploads entered the blob store concurrently", limit)
	case <-time.After(250 * time.Millisecond):
	}

	close(bs.release)
	wg.Wait()

	if peak := bs.peakConcurrency(); peak > limit {
		t.Errorf("peak concurrent uploads = %d, want <= %d", peak, limit)
	}
}

// TestUploadConcurrencyUnsetIsUnbounded documents that the limiter is opt-in: with
// no SetUploadConcurrency call the handler must not gate uploads at all, so tests
// and callers that never configure it are unaffected.
func TestUploadConcurrencyUnsetIsUnbounded(t *testing.T) {
	st := staging.New(staging.NewMemoryBlobStore(), staging.NewMemorySessionStore(), countingIDGen())
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), st, nil, nil, nil)

	if rec := monolithicPush(h, []byte("unbounded")); rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
}

// TestUploadSaturationReturns503 pins the client-visible behaviour when no slot
// frees within the wait budget: a retryable 503 with Retry-After, matching how the
// manifest gate reports pool saturation — NOT a hang and NOT a 500.
func TestUploadSaturationReturns503(t *testing.T) {
	bs := newBlockingBlobStore(4)
	st := staging.New(bs, staging.NewMemorySessionStore(), countingIDGen())
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), st, nil, nil, nil)
	h.SetUploadConcurrency(1)
	h.SetUploadWait(50 * time.Millisecond) // fail fast instead of queueing

	// Occupy the single slot for the rest of the test.
	go monolithicPush(h, []byte("holder"))
	select {
	case <-bs.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("holder never reached the blob store")
	}

	rec := monolithicPush(h, []byte("rejected"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("saturated upload: status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("saturated upload: missing Retry-After header")
	}

	close(bs.release)
}

// TestBeginUploadNotGated keeps the limiter scoped to requests that actually buffer
// bytes. A bodiless POST only mints an upload ID; holding a slot for it would let a
// burst of push starts trigger 503s that have nothing to do with memory pressure.
func TestBeginUploadNotGated(t *testing.T) {
	bs := newBlockingBlobStore(4)
	st := staging.New(bs, staging.NewMemorySessionStore(), countingIDGen())
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), st, nil, nil, nil)
	h.SetUploadConcurrency(1)
	h.SetUploadWait(50 * time.Millisecond)

	// Hold the only slot with a real blob upload.
	go monolithicPush(h, []byte("holder"))
	select {
	case <-bs.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("holder never reached the blob store")
	}

	req := httptest.NewRequest(http.MethodPost, "/v2/app/blobs/uploads/", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("begin upload while slots are full: status = %d, want 202", rec.Code)
	}

	close(bs.release)
}

// TestDefaultMaxUploadBytes pins the unconfigured chunk ceiling. It used to be
// 2 GiB, which no memory limit merlin runs under can absorb once the staging
// read-modify-write multiplies it; an oversized layer must fail as a clean 413
// rather than as an OOMKill that takes every concurrent push with it.
func TestDefaultMaxUploadBytes(t *testing.T) {
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, nil)
	if got := h.getMaxUploadBytes(); got != 512<<20 {
		t.Errorf("default max upload bytes = %d, want %d (512 MiB)", got, 512<<20)
	}
}
