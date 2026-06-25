package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	// Docker clients reject a manifest PUT 201 unless the response echoes the
	// canonical manifest digest in Docker-Content-Digest ("invalid checksum digest
	// format" otherwise). It must be the sha256 of the exact manifest bytes.
	wantDigest := dg(manifestBytes)
	if got := rec.Header().Get("Docker-Content-Digest"); got != wantDigest {
		t.Errorf("Docker-Content-Digest = %q, want %q", got, wantDigest)
	}
}

// TestManifestPUTAttestationForwarded verifies a buildx SLSA attestation manifest
// (in-toto layer, no filesystem) is forwarded to ACR verbatim — NOT run through the
// gate (which would tar-extract the in-toto JSON and 500).
func TestManifestPUTAttestationForwarded(t *testing.T) {
	h, fp := buildIntegrationHandler(t, trivy.Report{}, 2)

	// Stage the attestation's referenced blobs (config + in-toto layer) as the
	// docker client would before the manifest PUT, so they can be seeded to ACR.
	configBlob := []byte(`{"architecture":"amd64","os":"linux"}`)
	intotoBlob := []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`)
	configDg := uploadLayer(t, h, "app", configBlob)
	intotoDg := uploadLayer(t, h, "app", intotoBlob)

	attestation := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]interface{}{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDg},
		"layers": []map[string]interface{}{
			{"mediaType": "application/vnd.in-toto+json", "digest": intotoDg},
		},
	}
	body, _ := json.Marshal(attestation)
	// docker pushes the attestation by digest.
	digest := dg(body)
	req := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/"+digest, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("attestation PUT: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Docker-Content-Digest") != digest {
		t.Errorf("Docker-Content-Digest = %q, want %q", rec.Header().Get("Docker-Content-Digest"), digest)
	}
	// Its config + in-toto blobs must have been seeded to ACR first.
	if len(fp.PushedBlob) != 2 {
		t.Errorf("expected 2 seeded blobs (config + in-toto), got %d", len(fp.PushedBlob))
	}
	if len(fp.PushedManifest) != 1 {
		t.Fatalf("expected 1 verbatim manifest forward, got %d", len(fp.PushedManifest))
	}
	// forwarded by digest, to the configured registry/repo
	if want := "myreg.azurecr.io/app@" + digest; fp.PushedManifest[0] != want {
		t.Errorf("forward target = %q, want %q", fp.PushedManifest[0], want)
	}
	// must NOT have been gated/assembled (no image push)
	if len(fp.Pushed) != 0 {
		t.Errorf("attestation must not go through the image gate, got Pushed=%v", fp.Pushed)
	}
}

// TestManifestPUTIndexForwarded verifies an image index is forwarded to ACR verbatim.
func TestManifestPUTIndexForwarded(t *testing.T) {
	h, fp := buildIntegrationHandler(t, trivy.Report{}, 2)

	index := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]interface{}{
			{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:fc"},
		},
	}
	body, _ := json.Marshal(index)
	// docker pushes the index by tag.
	req := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/2.13.25", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("index PUT: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if len(fp.PushedManifest) != 1 {
		t.Fatalf("expected 1 verbatim manifest forward, got %d", len(fp.PushedManifest))
	}
	if want := "myreg.azurecr.io/app:2.13.25"; fp.PushedManifest[0] != want {
		t.Errorf("forward target = %q, want %q (index pushed by tag)", fp.PushedManifest[0], want)
	}
}

// TestManifestPUTIndexForwardFailureIs400 verifies that when forwarding fails
// (e.g. the gated image was rejected so its sub-manifest is absent in ACR), the
// push fails cleanly with 400 rather than publishing or 500ing.
func TestManifestPUTIndexForwardFailureIs400(t *testing.T) {
	h, fp := buildIntegrationHandler(t, trivy.Report{}, 2)
	fp.Err = context.DeadlineExceeded // simulate ACR rejecting the index

	index := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests":     []map[string]interface{}{{"digest": "sha256:fc"}},
	}
	body, _ := json.Marshal(index)
	req := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/v1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("failed index forward: status = %d, want 400", rec.Code)
	}
}

// TestManifestPUTSharedBlobConcurrent reproduces the production buildx race: two
// repos push the SAME layer blob; both gate concurrently. With content-addressed
// ref-counting, one push's cleanup must not delete the shared blob the other still
// needs — both must succeed (201), not spuriously 500.
func TestManifestPUTSharedBlobConcurrent(t *testing.T) {
	h, fp := buildIntegrationHandler(t, trivy.Report{}, 4)
	layer := layerWithOSID(t, "rhel") // same bytes => same digest, shared blob

	const repos = 6
	// Pre-upload the shared blob under each repo (each completion adds a ref).
	for i := 0; i < repos; i++ {
		uploadLayer(t, h, fmt.Sprintf("shared%d", i), layer)
	}
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": dg(layer)},
		"layers":        []map[string]interface{}{{"digest": dg(layer)}},
	}
	manifestBytes, _ := json.Marshal(manifest)

	statuses := make([]int, repos)
	var wg sync.WaitGroup
	for i := 0; i < repos; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v2/shared%d/manifests/v1", i), bytes.NewReader(manifestBytes))
			req.Header.Set("Authorization", "Bearer good")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			statuses[i] = rec.Code
		}(i)
	}
	wg.Wait()

	for i, s := range statuses {
		if s != http.StatusCreated {
			t.Errorf("shared%d: status = %d, want 201 (shared-blob cleanup race?)", i, s)
		}
	}
	if len(fp.Pushed) != repos {
		t.Errorf("ACR pushes = %d, want %d", len(fp.Pushed), repos)
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
