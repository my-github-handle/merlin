package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policies/baseimage"
	"github.com/merlin-gate/merlin/internal/policies/trivy"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
)

// buildIntegrationHandler assembles a handler with in-memory staging, pool, and fake ACR.
func buildIntegrationHandler(t *testing.T, trivyReport trivy.Report, poolSize int) (*Handler, *acr.FakePusher) {
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

// uploadLayer uploads a blob layer through the handler's upload path.
func uploadLayer(t *testing.T, h *Handler, repo string, layer []byte) string {
	t.Helper()
	digest := dg(layer)

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

	// PATCH the layer data
	req = httptest.NewRequest(http.MethodPatch, "/v2/"+repo+"/blobs/uploads/"+uploadID, bytes.NewReader(layer))
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Content-Range", "0-"+string(rune('0'+len(layer)-1)))
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

// TestManifestPUTUBILayerAccepted tests the happy path: upload a UBI layer, PUT manifest → 201 + ACR push.
func TestManifestPUTUBILayerAccepted(t *testing.T) {
	layer := layerWithOSID(t, "rhel")
	h, fp := buildIntegrationHandler(t, trivy.Report{}, 2)

	// Upload the layer
	layerDigest := uploadLayer(t, h, "testapp", layer)

	// Build a minimal manifest JSON
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"config": map[string]interface{}{
			"digest": layerDigest, // config and layer are the same for simplicity
		},
		"layers": []map[string]interface{}{
			{"digest": layerDigest},
		},
	}
	manifestBytes, _ := json.Marshal(manifest)

	// PUT the manifest
	req := httptest.NewRequest(http.MethodPut, "/v2/testapp/manifests/v1", bytes.NewReader(manifestBytes))
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

// TestManifestPUTPoolSaturated tests that when the pool is saturated, the handler returns 503 + Retry-After.
func TestManifestPUTPoolSaturated(t *testing.T) {
	layer := layerWithOSID(t, "rhel")
	// Create a pool of size 1
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
	h.SetGateTimeout(5 * time.Second) // long enough for first request to stay alive while blocking

	// Upload the first layer
	layerDigest := uploadLayer(t, h, "app1", layer)

	// Build manifest
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": layerDigest},
		"layers":        []map[string]interface{}{{"digest": layerDigest}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	// Start a gate in the background that occupies the pool slot
	go func() {
		req := httptest.NewRequest(http.MethodPut, "/v2/app1/manifests/v1", bytes.NewReader(manifestBytes))
		req.Header.Set("Authorization", "Bearer good")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}()

	// Wait for the blocking policy to enter (occupy the slot)
	<-bp.entered

	// Now attempt a second manifest PUT with the saturated pool
	layer2 := layerWithOSID(t, "rhel")
	digest2 := uploadLayer(t, h, "app2", layer2)
	manifest2 := map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": digest2},
		"layers":        []map[string]interface{}{{"digest": digest2}},
	}
	manifestBytes2, _ := json.Marshal(manifest2)

	// Create request with short timeout context
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

// TestManifestPUTIncompletePush tests that when referenced blobs are missing, we get 400.
func TestManifestPUTIncompletePush(t *testing.T) {
	h, _ := buildIntegrationHandler(t, trivy.Report{}, 2)

	// Build a manifest referencing a digest that was never uploaded
	fakeDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": fakeDigest},
		"layers":        []map[string]interface{}{{"digest": fakeDigest}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	req := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/v1", bytes.NewReader(manifestBytes))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("incomplete push: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "incomplete") && !strings.Contains(body, "missing") {
		t.Errorf("incomplete push: body should mention missing blobs, got %q", body)
	}
}

// blockingPolicy is a test policy that blocks until released (for pool saturation test).
type blockingPolicy struct {
	release chan struct{}
	entered chan struct{}
}

func (b blockingPolicy) Name() string { return "block" }
func (b blockingPolicy) Evaluate(ctx context.Context, _ policy.StagedImage) (policy.Verdict, error) {
	b.entered <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
		return policy.Verdict{}, ctx.Err()
	}
	return policy.Verdict{Passed: true}, nil
}

// Reuse layerWithOSID and dg from push_integration_test.go
