package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policies/baseimage"
	"github.com/merlin-gate/merlin/internal/policies/trivy"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
)

// TestHTTPPushUBIGood tests the happy path: upload a UBI (rhel) layer + config through the
// real HTTP handler, PUT manifest → 201 + ACR push + scan report URL.
func TestHTTPPushUBIGood(t *testing.T) {
	layer := layerWithOSID(t, "rhel")
	h, fp := buildHTTPHandler(t, trivy.Report{}, 2)

	repo := "testapp"
	ref := "v1"

	// Upload the layer blob
	layerDigest := httpUploadBlob(t, h, repo, layer)

	// Upload a config blob (can be same as layer for this test)
	configDigest := httpUploadBlob(t, h, repo, layer)

	// Build a Docker V2 manifest JSON
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"config": map[string]interface{}{
			"digest": configDigest,
		},
		"layers": []map[string]interface{}{
			{"digest": layerDigest},
		},
	}
	manifestBytes, _ := json.Marshal(manifest)

	// PUT the manifest
	req := httptest.NewRequest(http.MethodPut, "/v2/"+repo+"/manifests/"+ref, bytes.NewReader(manifestBytes))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("manifest PUT: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if len(fp.Pushed) != 1 {
		t.Errorf("expected ACR push, got %d pushes", len(fp.Pushed))
	}
	reportURL := rec.Header().Get("X-Merlin-Scan-Report-URL")
	if reportURL == "" {
		t.Error("missing X-Merlin-Scan-Report-URL header")
	}
}

// TestHTTPPushCriticalCVE tests that a CRITICAL CVE finding rejects the push with 400 + no ACR push.
func TestHTTPPushCriticalCVE(t *testing.T) {
	layer := layerWithOSID(t, "rhel")
	report := trivy.Report{
		Findings: []policy.Finding{{CVE: "CVE-2024-1", Severity: "CRITICAL", Pkg: "openssl", Version: "1.1.1"}},
	}
	h, fp := buildHTTPHandler(t, report, 2)

	repo := "badapp"
	ref := "v1"

	layerDigest := httpUploadBlob(t, h, repo, layer)
	configDigest := httpUploadBlob(t, h, repo, layer)

	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": configDigest},
		"layers":        []map[string]interface{}{{"digest": layerDigest}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	req := httptest.NewRequest(http.MethodPut, "/v2/"+repo+"/manifests/"+ref, bytes.NewReader(manifestBytes))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("CRITICAL CVE: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if len(fp.Pushed) != 0 {
		t.Error("must not forward a rejected image with CRITICAL CVE")
	}
}

// TestHTTPPushAlpineRejected tests that an Alpine base layer is rejected with 400 + no ACR push.
func TestHTTPPushAlpineRejected(t *testing.T) {
	layer := layerWithOSID(t, "alpine")
	h, fp := buildHTTPHandler(t, trivy.Report{}, 2)

	repo := "alpineapp"
	ref := "v1"

	layerDigest := httpUploadBlob(t, h, repo, layer)
	configDigest := httpUploadBlob(t, h, repo, layer)

	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": configDigest},
		"layers":        []map[string]interface{}{{"digest": layerDigest}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	req := httptest.NewRequest(http.MethodPut, "/v2/"+repo+"/manifests/"+ref, bytes.NewReader(manifestBytes))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Alpine base: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if len(fp.Pushed) != 0 {
		t.Error("must not forward a non-approved base image")
	}
}

// TestHTTPPushUnauthenticated tests that a request without valid auth returns 401 + WWW-Authenticate.
func TestHTTPPushUnauthenticated(t *testing.T) {
	n := 0
	st := staging.New(staging.NewMemoryBlobStore(), staging.NewMemorySessionStore(), func() string {
		n++
		return "u" + string(rune('0'+n))
	})
	tp := trivy.New(staticRunner{report: trivy.Report{}}, "CRITICAL")
	bp := baseimage.New([]string{"rhel", "wolfi", "chainguard"})
	rt := router.New(policy.NewEngine(tp, bp))
	fp := &acr.FakePusher{}
	o := &Outcome{Pusher: fp, ReportBaseURL: "/reports"}
	// Use fakeAuth{ok: false} for unauthenticated test
	h := NewHandler(fakeAuth{ok: false}, st, rt, o, "myreg.azurecr.io", nil)

	// Try to access /v2/ without auth
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: status = %d, want 401", rec.Code)
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

// TestHTTPPushSaturated tests that when the pool is saturated, the handler returns 503 + Retry-After.
func TestHTTPPushSaturated(t *testing.T) {
	layer := layerWithOSID(t, "rhel")

	// Build a handler with pool size 1 and a blocking policy
	n := 0
	st := staging.New(staging.NewMemoryBlobStore(), staging.NewMemorySessionStore(), func() string {
		n++
		return "u" + string(rune('0'+n))
	})
	bp := blockingPolicy{release: make(chan struct{}), entered: make(chan struct{}, 2)}
	rt := router.New(policy.NewEngine(bp))
	pool := router.NewPool(rt, 1)
	fp := &acr.FakePusher{}
	o := &Outcome{Pusher: fp, ReportBaseURL: "/reports"}
	h := NewHandler(fakeAuth{ok: true}, st, rt, o, "myreg.azurecr.io", nil)
	h.SetPool(pool)
	h.SetGateTimeout(5 * time.Second) // long enough for first request to stay alive

	// Upload the first layer
	layerDigest := httpUploadBlob(t, h, "app1", layer)
	configDigest := httpUploadBlob(t, h, "app1", layer)

	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": configDigest},
		"layers":        []map[string]interface{}{{"digest": layerDigest}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	// Start a goroutine that occupies the pool slot
	go func() {
		req := httptest.NewRequest(http.MethodPut, "/v2/app1/manifests/v1", bytes.NewReader(manifestBytes))
		req.Header.Set("Authorization", "Bearer good")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}()

	// Wait for the blocking policy to enter (occupy the slot)
	<-bp.entered

	// Now attempt a second manifest PUT with the saturated pool, using a short timeout
	layer2 := layerWithOSID(t, "rhel")
	digest2 := httpUploadBlob(t, h, "app2", layer2)
	configDigest2 := httpUploadBlob(t, h, "app2", layer2)

	manifest2 := map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": configDigest2},
		"layers":        []map[string]interface{}{{"digest": digest2}},
	}
	manifestBytes2, _ := json.Marshal(manifest2)

	// Build a short timeout context to trigger ErrSaturated quickly
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	req := httptest.NewRequest(http.MethodPut, "/v2/app2/manifests/v2", bytes.NewReader(manifestBytes2))
	req = req.WithContext(ctx2)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("saturated pool: status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("saturated pool: missing Retry-After header")
	}

	// Release the blocking policy
	close(bp.release)
}

// buildHTTPHandler assembles a handler with in-memory staging, pool, and fake ACR for HTTP tests.
func buildHTTPHandler(t *testing.T, trivyReport trivy.Report, poolSize int) (*Handler, *acr.FakePusher) {
	t.Helper()
	n := 0
	st := staging.New(staging.NewMemoryBlobStore(), staging.NewMemorySessionStore(), func() string {
		n++
		return "u" + string(rune('0'+n))
	})
	tp := trivy.New(staticRunner{report: trivyReport}, "CRITICAL")
	bp := baseimage.New([]string{"rhel", "wolfi", "chainguard"})
	rt := router.New(policy.NewEngine(tp, bp))
	pool := router.NewPool(rt, poolSize)
	fp := &acr.FakePusher{}
	o := &Outcome{Pusher: fp, ReportBaseURL: "/reports"}
	h := NewHandler(fakeAuth{ok: true}, st, rt, o, "myreg.azurecr.io", nil)
	h.SetPool(pool)
	h.SetGateTimeout(5 * time.Second)
	return h, fp
}

// httpUploadBlob uploads a blob through the real HTTP V2 sequence:
// POST /v2/<repo>/blobs/uploads/ → PATCH with data → PUT ?digest=<digest>.
func httpUploadBlob(t *testing.T, h *Handler, repo string, blob []byte) string {
	t.Helper()
	digest := dg(blob)

	// POST to begin upload
	req := httptest.NewRequest(http.MethodPost, "/v2/"+repo+"/blobs/uploads/", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST upload: status = %d, want 202", rec.Code)
	}
	uploadID := rec.Header().Get("Docker-Upload-UUID")
	if uploadID == "" {
		t.Fatalf("POST upload: missing Docker-Upload-UUID")
	}

	// PATCH the blob data
	req = httptest.NewRequest(http.MethodPatch, "/v2/"+repo+"/blobs/uploads/"+uploadID, bytes.NewReader(blob))
	req.Header.Set("Authorization", "Bearer good")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("PATCH upload: status = %d, want 202", rec.Code)
	}

	// PUT to complete
	req = httptest.NewRequest(http.MethodPut, "/v2/"+repo+"/blobs/uploads/"+uploadID+"?digest="+digest, nil)
	req.Header.Set("Authorization", "Bearer good")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT complete: status = %d, want 201", rec.Code)
	}

	return digest
}

// blockingPolicy is reused from manifest_flow_test.go (defined there).
