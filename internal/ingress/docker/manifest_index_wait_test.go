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

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policies/grype"
)

// missingReferenceErr is the error ACR returns when an index names a sub-manifest the
// registry does not have — copied from a live 400 body.
func missingReferenceErr(digest string) error {
	return &transport.Error{
		StatusCode: http.StatusBadRequest,
		Errors: []transport.Diagnostic{{
			Code:    transport.ManifestBlobUnknownErrorCode,
			Message: "blob unknown to registry",
			Detail:  digest,
		}},
	}
}

// indexBody builds a tag-addressed image index referencing one sub-manifest, the
// shape buildx PUTs last in a push.
func indexBody(subDigest string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]interface{}{
			{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": subDigest},
		},
	})
	return body
}

// putIndex PUTs an index by tag and returns the recorder.
func putIndex(t *testing.T, h *Handler, tag string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/"+tag, bytes.NewReader(body))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestIndexForwardWaitsForAnAsyncPromotionToLand is the regression test for a live
// failure: deferring ACR publication to the promotion worker broke an ordering the
// index forward silently depended on.
//
// buildx PUTs the image manifest, then the index ~70ms later. While publication was
// synchronous, the image was in ACR before the gate answered 201, so the index's
// reference always resolved. With a promotion queue the image is merely *enqueued*,
// so the index PUT arrived first and ACR rejected it with MANIFEST_BLOB_UNKNOWN —
// the client's whole push failed with 400 and the image landed in ACR UNTAGGED.
//
// Waiting is safe in the one direction that matters: a rejected image is never
// promoted, so its reference never appears and the wait still ends in a 400.
func TestIndexForwardWaitsForAnAsyncPromotionToLand(t *testing.T) {
	fp := &acr.FakePusher{ManifestErrs: []error{
		missingReferenceErr("sha256:cb04f117"), // promotion still queued
		missingReferenceErr("sha256:cb04f117"), // worker claimed it, still pushing
	}}
	h := buildIntegrationHandlerWithPusher(t, grype.Report{}, 2, fp)
	h.indexWait = 2 * time.Second
	h.indexPoll = time.Millisecond

	rec := putIndex(t, h, "v1", indexBody("sha256:cb04f117"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("index PUT: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if got := fp.ManifestAttempts(); got != 3 {
		t.Errorf("PushManifest attempts = %d, want 3 (two misses then the promotion landing)", got)
	}
	if len(fp.PushedManifest) != 1 || fp.PushedManifest[0] != "myreg.azurecr.io/app:v1" {
		t.Errorf("forwarded = %v, want one push to myreg.azurecr.io/app:v1", fp.PushedManifest)
	}
}

// TestIndexForwardGivesUpAndSaysTheImageIsStillPublishing keeps the wait bounded and
// the failure legible. An unbounded wait would hold a scan-slot-free request open
// forever behind a stuck queue; a bare "manifest not published" would send the reader
// hunting for a rejection that never happened.
func TestIndexForwardGivesUpAndSaysTheImageIsStillPublishing(t *testing.T) {
	fp := &acr.FakePusher{Err: missingReferenceErr("sha256:cb04f117")}
	h := buildIntegrationHandlerWithPusher(t, grype.Report{}, 2, fp)
	h.indexWait = 40 * time.Millisecond
	h.indexPoll = 5 * time.Millisecond

	start := time.Now()
	rec := putIndex(t, h, "v1", indexBody("sha256:cb04f117"))
	elapsed := time.Since(start)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("index PUT: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if elapsed > 2*time.Second {
		t.Errorf("gave up after %s, want ~the configured 40ms wait", elapsed)
	}
	if got := fp.ManifestAttempts(); got < 2 {
		t.Errorf("PushManifest attempts = %d, want more than one (it must retry within the wait)", got)
	}
	// The body is the only thing the pushing client sees, so it has to distinguish
	// "still publishing, retry" from "rejected, do not retry".
	body := rec.Body.String()
	if !strings.Contains(body, "sha256:cb04f117") {
		t.Errorf("body = %q, want it to name the unresolved reference", body)
	}
	if !strings.Contains(body, "publish") {
		t.Errorf("body = %q, want it to say the referenced image is still publishing", body)
	}
}

// TestIndexForwardDoesNotWaitOnAnUnrelatedFailure keeps every other error fast. A
// credential or target problem cannot be waited out, and burning the full window on
// one turns a clear failure into a slow, vague one.
func TestIndexForwardDoesNotWaitOnAnUnrelatedFailure(t *testing.T) {
	fp := &acr.FakePusher{Err: &transport.Error{
		StatusCode: http.StatusUnauthorized,
		Errors:     []transport.Diagnostic{{Code: transport.UnauthorizedErrorCode}},
	}}
	h := buildIntegrationHandlerWithPusher(t, grype.Report{}, 2, fp)
	// Short, not long: if the classification regressed, this must fail on the attempt
	// count in milliseconds rather than by hanging out the whole wait.
	h.indexWait = 100 * time.Millisecond
	h.indexPoll = time.Millisecond

	rec := putIndex(t, h, "v1", indexBody("sha256:cb04f117"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("index PUT: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := fp.ManifestAttempts(); got != 1 {
		t.Errorf("PushManifest attempts = %d, want exactly 1 (unauthorized is not waitable)", got)
	}
}

// TestAttestationForwardDoesNotWaitForReferences scopes the wait to indexes. An
// attestation's references are blobs THIS handler seeds synchronously a few lines
// earlier (seedAttestationBlobs), so a missing reference there is a fault in the seed
// — waiting on it would only delay the report of our own bug.
func TestAttestationForwardDoesNotWaitForReferences(t *testing.T) {
	// Only the manifest forward fails; blob seeding must still succeed, or this test
	// would never reach the code it is about. One entry, so a retry would SUCCEED —
	// making "it retried" visible as a 201 rather than an equally-400 pass.
	fp := &acr.FakePusher{ManifestErrs: []error{missingReferenceErr("sha256:deadbeef")}}
	h := buildIntegrationHandlerWithPusher(t, grype.Report{}, 2, fp)
	h.indexWait = 100 * time.Millisecond
	h.indexPoll = time.Millisecond

	// Stage the attestation's blobs so seeding succeeds and the forward is actually
	// reached — otherwise this test would pass no matter what the forward does.
	configDg := uploadLayer(t, h, "app", []byte(`{"architecture":"amd64","os":"linux"}`))
	intotoDg := uploadLayer(t, h, "app", []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`))

	// An attestation is an image-media-type manifest whose only layer is in-toto.
	body, _ := json.Marshal(map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]interface{}{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDg},
		"layers": []map[string]interface{}{
			{"mediaType": "application/vnd.in-toto+json", "digest": intotoDg},
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/"+dg(body), bytes.NewReader(body))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("attestation PUT: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := fp.ManifestAttempts(); got != 1 {
		t.Errorf("PushManifest attempts = %d, want exactly 1 (an attestation's blobs are seeded here, not promoted)", got)
	}
}

// TestIndexForwardStopsWaitingWhenTheClientLeaves. The wait exists to answer a client
// that is still there; once it has hung up there is no one to answer, and holding the
// goroutine (and the connection's slot) only burns capacity that other pushes need.
func TestIndexForwardStopsWaitingWhenTheClientLeaves(t *testing.T) {
	fp := &acr.FakePusher{Err: missingReferenceErr("sha256:cb04f117")}
	h := buildIntegrationHandlerWithPusher(t, grype.Report{}, 2, fp)
	// Long enough that finishing quickly can only be cancellation, not the deadline.
	h.indexWait = 30 * time.Second
	h.indexPoll = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/v1", bytes.NewReader(indexBody("sha256:cb04f117"))).WithContext(ctx)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := fp.ManifestAttempts(); got != 1 {
		t.Errorf("PushManifest attempts = %d, want 1 (no retry after the client is gone)", got)
	}
}
