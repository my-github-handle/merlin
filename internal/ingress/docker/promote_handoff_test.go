package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policies/grype"
	"github.com/merlin-gate/merlin/internal/promote"
)

// blockingPusher stands in for an ACR that answers slower than the client's 30s
// response-header ceiling. Push parks until released, so any test whose handler
// completes proves the push was not on the critical path.
type blockingPusher struct {
	block chan struct{}
	mu    sync.Mutex
	n     int
}

func (p *blockingPusher) Push(ctx context.Context, _, _ string) error {
	p.mu.Lock()
	p.n++
	p.mu.Unlock()
	select {
	case <-p.block:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *blockingPusher) PushManifest(context.Context, []byte, string, string) error { return nil }
func (p *blockingPusher) PushBlob(context.Context, []byte, string, string) error     { return nil }

func (p *blockingPusher) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// fakePromoter records the jobs handed off for deferred promotion.
type fakePromoter struct {
	err error

	mu     sync.Mutex
	queued []promote.Job
}

func (f *fakePromoter) Promote(_ context.Context, j promote.Job) error {
	if f.err != nil {
		return f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queued = append(f.queued, j)
	return nil
}

func (f *fakePromoter) jobs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queued)
}

func (f *fakePromoter) last() (promote.Job, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queued) == 0 {
		return promote.Job{}, false
	}
	return f.queued[len(f.queued)-1], true
}

// pushManifest uploads a layer and PUTs a manifest referencing it, returning the
// recorder. osID selects the base image the layer reports, which is what the
// base-image policy passes or rejects on.
func pushManifest(t *testing.T, h *Handler, repo, ref, osID string) *httptest.ResponseRecorder {
	t.Helper()
	layerDigest := uploadLayer(t, h, repo, layerWithOSID(t, osID))
	manifestBytes, _ := json.Marshal(map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": layerDigest},
		"layers":        []map[string]interface{}{{"digest": layerDigest}},
	})
	req := httptest.NewRequest(http.MethodPut, "/v2/"+repo+"/manifests/"+ref, bytes.NewReader(manifestBytes))
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestManifestRespondsWithoutWaitingForACR is the whole point of the change: both
// push clients hardcode a 30s ResponseHeaderTimeout, so the manifest PUT must not
// be held across the ACR push.
func TestManifestRespondsWithoutWaitingForACR(t *testing.T) {
	slow := &blockingPusher{block: make(chan struct{})}
	defer close(slow.block)
	prom := &fakePromoter{}
	h := buildIntegrationHandlerWithPusher(t, grype.Report{}, 2, slow)
	h.SetPromoter(prom)

	done := make(chan int, 1)
	go func() { done <- pushManifest(t, h, "app", "v1", "rhel").Code }()

	select {
	case code := <-done:
		if code != http.StatusCreated {
			t.Errorf("status = %d, want 201", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not respond within 5s; ACR push is still on the critical path")
	}
	if slow.calls() != 0 {
		t.Error("handler pushed to ACR synchronously")
	}
	if prom.jobs() != 1 {
		t.Errorf("enqueued %d promotion jobs, want 1", prom.jobs())
	}
}

// TestRejectedImageIsNeverEnqueued is the security-critical assertion of the whole
// change. Deferring publication must not turn the gate into an advisory: a rejected
// image must never reach the promotion queue, because everything on that queue is
// published without a second verdict.
func TestRejectedImageIsNeverEnqueued(t *testing.T) {
	prom := &fakePromoter{}
	h, fp := buildIntegrationHandler(t, grype.Report{}, 2)
	h.SetPromoter(prom)

	// alpine fails the base-image policy. Chosen over a CRITICAL CVE deliberately:
	// the vulnerability gate's enforcement is configurable, the base-image allowlist
	// is not, so this test cannot be silently disarmed by a config change.
	rec := pushManifest(t, h, "app", "v1", "alpine")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if prom.jobs() != 0 {
		t.Fatal("a rejected image was enqueued for ACR promotion")
	}
	if len(fp.Pushed) != 0 {
		t.Error("a rejected image was pushed to ACR")
	}
}

// TestPromotionJobCarriesEverythingTheWorkerNeeds pins the hand-off payload. The
// handler is the last scope that holds the resolved tenant, the scratch dir, and the
// staged blob digests; anything it omits is either an image published to the wrong
// registry or a permanent disk/ref-count leak, and neither is visible at the call
// site of the worker.
func TestPromotionJobCarriesEverythingTheWorkerNeeds(t *testing.T) {
	prom := &fakePromoter{}
	h, _ := buildIntegrationHandler(t, grype.Report{}, 2)
	h.SetPromoter(prom)

	if code := pushManifest(t, h, "app", "v1", "rhel").Code; code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", code)
	}
	job, ok := prom.last()
	if !ok {
		t.Fatal("no promotion job enqueued")
	}
	// Tenant PREFIX, not repo: two tenants may host the same repo name against
	// different registries (internal/tenant/resolver.go PrefixFromHost).
	if job.Tenant != "c3dev" {
		t.Errorf("Tenant = %q, want c3dev; the worker cannot resolve the right ACR without it", job.Tenant)
	}
	if job.Repo != "app" || job.Ref != "v1" {
		t.Errorf("Repo/Ref = %q/%q, want app/v1", job.Repo, job.Ref)
	}
	if job.Target != "myreg.azurecr.io/app:v1" {
		t.Errorf("Target = %q, want myreg.azurecr.io/app:v1", job.Target)
	}
	if job.OCIPath == "" || job.ScratchDir == "" {
		t.Errorf("OCIPath/ScratchDir = %q/%q; the worker has nothing to push and nothing to clean up",
			job.OCIPath, job.ScratchDir)
	}
	// Cleanup releases staged blob ref-counts by ConfigDig + Layers. Omitting them
	// leaks every staged blob of every push, forever.
	if job.ConfigDig == "" || len(job.Layers) == 0 {
		t.Errorf("ConfigDig/Layers = %q/%v; staged blob refs would never be released",
			job.ConfigDig, job.Layers)
	}
	if job.Digest == "" {
		t.Error("Digest empty; a failed promotion could not be recorded against the image")
	}
	// The exact manifest bytes are the only thing that lets a SIBLING replica rebuild
	// the OCI layout: scratch is a per-pod emptyDir, so the pod that claims the job is
	// often not the pod that assembled it. Without them that job is unpromotable.
	if len(job.Manifest) == 0 {
		t.Error("Manifest empty; a sibling replica could not rebuild the OCI layout")
	}
	// The report URL handed to the client must name the same push the audit row and
	// any later promotion-failure row use, or the report 404s.
	if job.PushID == "" {
		t.Error("PushID empty; the report URL and the audit row would not agree")
	}
}

// TestPromotedPushLeavesScratchForTheWorker pins the lifetime hazard the deferral
// creates. handleManifest used to delete the scratch dir in a defer; once promotion
// outlives the request, that defer would delete the OCI layout out from under the
// worker and every promotion would fail on a missing directory.
func TestPromotedPushLeavesScratchForTheWorker(t *testing.T) {
	prom := &fakePromoter{}
	h, _ := buildIntegrationHandler(t, grype.Report{}, 2)
	h.SetPromoter(prom)

	if code := pushManifest(t, h, "app", "v1", "rhel").Code; code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", code)
	}
	job, ok := prom.last()
	if !ok {
		t.Fatal("no promotion job enqueued")
	}
	if _, err := os.Stat(job.OCIPath); err != nil {
		t.Errorf("OCI layout %s is gone after the handler returned: %v", job.OCIPath, err)
	}
}

// TestFailedEnqueueCleansUpAndReports401 covers the branch that is easy to get
// wrong: if the enqueue fails, the worker owns nothing, so the handler must still
// clean up AND must not report a pass. Setting `promoted` unconditionally after
// Apply (rather than inside the publish closure) would leak the scratch dir on
// exactly this path.
func TestFailedEnqueueCleansUpAndReports502(t *testing.T) {
	prom := &fakePromoter{err: errors.New("valkey down")}
	h, _ := buildIntegrationHandler(t, grype.Report{}, 2)
	h.SetPromoter(prom)

	before := scratchDirCount(t, h)
	rec := pushManifest(t, h, "app", "v1", "rhel")

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502; a push that was never queued must not report success", rec.Code)
	}
	if after := scratchDirCount(t, h); after != before {
		t.Errorf("scratch dirs = %d, want %d; nothing owns this layout, so the handler must remove it", after, before)
	}
}

// countingPromoter reports a fixed backlog. It implements PendingCounter as well as
// Promoter, which is how the handler learns the queue depth without the Promoter
// interface growing a second method that every fake would have to implement.
type countingPromoter struct {
	fakePromoter
	depth int
	err   error
}

func (c *countingPromoter) Pending(context.Context) (int, error) { return c.depth, c.err }

// TestSaturatedPromotionQueueShedsLoad is the disk bound on deferred promotion.
// Answering 201 while the job is still queued means the only thing limiting local
// scratch is the worker's drain rate, and scratch is a per-pod emptyDir: a burst of
// large pushes fills the volume and every concurrent push fails on assemble. A
// retryable 503 puts the backpressure back on the client instead.
func TestSaturatedPromotionQueueShedsLoad(t *testing.T) {
	prom := &countingPromoter{depth: 4}
	h, fp := buildIntegrationHandler(t, grype.Report{}, 2)
	h.SetPromoter(prom)
	h.SetMaxPendingPromotions(4)

	before := scratchDirCount(t, h)
	rec := pushManifest(t, h, "app", "v1", "rhel")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when the promotion backlog is at its bound", rec.Code)
	}
	// Retry-After is what makes this a load-shed rather than a failed build: without
	// it a docker client treats the 503 as terminal.
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on a saturated 503; the client cannot know to retry")
	}
	if prom.jobs() != 0 {
		t.Error("job was enqueued despite the queue being at its bound")
	}
	if len(fp.Pushed) != 0 {
		t.Error("image reached ACR on a shed push")
	}
	// The whole point is to not consume disk: the reject must land BEFORE assembly.
	if after := scratchDirCount(t, h); after != before {
		t.Errorf("scratch dirs = %d, want %d; a shed push must not assemble an image", after, before)
	}
}

// TestPromotionQueueDepthFailureDoesNotBlockPushes pins the fail-open direction. A
// Valkey blip that makes LLEN fail must not reject a scanned, passing image: the
// bound is a disk safeguard, and treating an unknown depth as saturated would turn
// one flaky read into a full outage of the gate.
func TestPromotionQueueDepthFailureDoesNotBlockPushes(t *testing.T) {
	prom := &countingPromoter{err: errors.New("valkey timeout")}
	h, _ := buildIntegrationHandler(t, grype.Report{}, 2)
	h.SetPromoter(prom)
	h.SetMaxPendingPromotions(1)

	if code := pushManifest(t, h, "app", "v1", "rhel").Code; code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; an unreadable queue depth must not fail a passing push", code)
	}
	if prom.jobs() != 1 {
		t.Errorf("enqueued jobs = %d, want 1", prom.jobs())
	}
}

// TestUnboundedPromotionQueueAdmitsEverything keeps the default behaviour: no
// configured bound means no admission check, so hermetic tests and single-binary dev
// are unaffected.
func TestUnboundedPromotionQueueAdmitsEverything(t *testing.T) {
	prom := &countingPromoter{depth: 10_000}
	h, _ := buildIntegrationHandler(t, grype.Report{}, 2)
	h.SetPromoter(prom) // no SetMaxPendingPromotions

	if code := pushManifest(t, h, "app", "v1", "rhel").Code; code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 with no bound configured", code)
	}
}

// TestSynchronousPushStillWorksWithoutAPromoter keeps the hermetic and
// single-binary dev configurations working: a nil promoter means publish inline.
func TestSynchronousPushStillWorksWithoutAPromoter(t *testing.T) {
	h, fp := buildIntegrationHandler(t, grype.Report{}, 2)

	if code := pushManifest(t, h, "app", "v1", "rhel").Code; code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", code)
	}
	if len(fp.Pushed) != 1 {
		t.Fatalf("ACR pushes = %d, want 1 (no promoter means publish inline)", len(fp.Pushed))
	}
}

// scratchDirCount counts assemble scratch dirs under the handler's scratch base, so
// a leak is observable without knowing the individual directory names.
func scratchDirCount(t *testing.T, h *Handler) int {
	t.Helper()
	base := h.scratchBaseDir
	if base == "" {
		base = os.TempDir()
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read scratch base %s: %v", base, err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) > 16 && e.Name()[:16] == "merlin-assemble-" {
			n++
		}
	}
	return n
}
