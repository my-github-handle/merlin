package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policies/grype"
)

// pausingRunner stands in for the grype child process. It blocks inside Scan until the
// test releases it, then reports what the scan's own context looked like at that
// moment — which is the whole question this file is about.
//
// killOnCancel reproduces exec.CommandContext exactly: Go sends SIGKILL when the
// context ends, and .Output() surfaces that as "signal: killed" with empty stderr. That
// is the audit row the live gate was full of.
type pausingRunner struct {
	started      chan struct{}
	proceed      chan struct{}
	killOnCancel bool
	failWith     error // returned regardless of the context, e.g. a kernel OOM kill

	mu     sync.Mutex
	ctxErr error
	scans  int
}

func newPausingRunner() *pausingRunner {
	return &pausingRunner{started: make(chan struct{}), proceed: make(chan struct{}), killOnCancel: true}
}

func (r *pausingRunner) Scan(ctx context.Context, _ string) (grype.Report, error) {
	r.mu.Lock()
	r.scans++
	r.mu.Unlock()
	close(r.started)

	select {
	case <-r.proceed:
	case <-ctx.Done():
		// A scan tied to its caller's context dies here. Waiting for proceed as well
		// would deadlock the pre-fix behaviour instead of failing it.
	case <-time.After(10 * time.Second):
		panic("pausingRunner: never released")
	}

	r.mu.Lock()
	r.ctxErr = ctx.Err()
	r.mu.Unlock()

	if r.failWith != nil {
		return grype.Report{}, r.failWith
	}
	if r.killOnCancel && ctx.Err() != nil {
		return grype.Report{}, errors.New("signal: killed")
	}
	return grype.Report{}, nil
}

// observedCtxErr is the scan context's error as the scan saw it. nil means the scan was
// left alone to finish.
func (r *pausingRunner) observedCtxErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ctxErr
}

// ctxPusher is an acr.Pusher that refuses a push whose context is already done, the way
// a real registry client does. acr.FakePusher ignores its context, so a test using it
// could not tell a publication that survived the client from one that never looked.
type ctxPusher struct {
	mu     sync.Mutex
	pushed []string
}

func (p *ctxPusher) Push(ctx context.Context, _, target string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pushed = append(p.pushed, target)
	return nil
}

func (p *ctxPusher) PushManifest(ctx context.Context, _ []byte, _, _ string) error {
	return ctx.Err()
}

func (p *ctxPusher) PushBlob(ctx context.Context, _ []byte, _, _ string) error {
	return ctx.Err()
}

func (p *ctxPusher) targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.pushed...)
}

// startPush stages a layer and PUTs its manifest on a context the test controls,
// concurrently. It returns the client's cancel func and a channel closed once the
// handler has answered.
func startPush(t *testing.T, h *Handler, repo, tag string) (cancel func(), done <-chan struct{}, rec *httptest.ResponseRecorder) {
	t.Helper()
	layerDigest := uploadLayer(t, h, repo, layerWithOSID(t, "rhel"))
	manifestBytes, _ := json.Marshal(map[string]interface{}{
		"schemaVersion": 2,
		"config":        map[string]interface{}{"digest": layerDigest},
		"layers":        []map[string]interface{}{{"digest": layerDigest}},
	})

	ctx, cancelFn := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPut, "/v2/"+repo+"/manifests/"+tag, bytes.NewReader(manifestBytes)).WithContext(ctx)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec = httptest.NewRecorder()

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		h.ServeHTTP(rec, req)
	}()
	return cancelFn, finished, rec
}

// TestScanSurvivesTheClientGivingUp is the regression test for the largest infra_error
// class on the live gate: 72 rows of "signal: killed" with a median duration of 31.1s,
// sitting exactly on the docker/buildx hardcoded ~30s response-header ceiling.
//
// It was read as memory pressure — the per-scan memory bound had landed the same day —
// but there were zero OOMKilled events and zero restarts. The real cause was the scan
// context being derived from the REQUEST context: the client gave up at 30s, the context
// canceled, and exec.CommandContext SIGKILLed grype mid-scan. Fail-closed turned that
// into an infra_error, and the pool slot had been held for 31s for no result at all.
//
// Once a slot is held and grype is running, the scan finishes: the decision is worth
// recording even though nobody is left to receive it, and a client that retries then
// finds the work done rather than paying for it twice.
func TestScanSurvivesTheClientGivingUp(t *testing.T) {
	r := newPausingRunner()
	fp := &ctxPusher{}
	h := buildIntegrationHandlerWithRunner(t, r, 1, fp)
	rec := &spyRecorder{}
	h.outcome.Recorder = rec

	cancel, done, _ := startPush(t, h, "app", "v1")
	<-r.started
	cancel() // the client's 30s ceiling, in test time
	close(r.proceed)
	<-done

	if err := r.observedCtxErr(); err != nil {
		t.Errorf("scan context error = %v, want nil (the scan holds a slot; it must not be killed with the request)", err)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("audit rows = %d, want 1 (the decision must be recorded even with no one to answer)", len(rec.calls))
	}
	d := rec.calls[0].decision
	if !d.Passed || d.InfraError {
		t.Errorf("row = {passed:%v infra:%v detail:%q}, want a clean pass", d.Passed, d.InfraError, d.ErrorDetail)
	}
}

// TestAbandonedPushIsStillPublished covers the other half of not discarding the work: a
// scan that finishes for a departed client must still publish. Leaving publication on
// the request context would trade the "signal: killed" row for a "publish: context
// canceled" row — the scan completed, and the result was thrown away at the last step.
func TestAbandonedPushIsStillPublished(t *testing.T) {
	r := newPausingRunner()
	fp := &ctxPusher{}
	h := buildIntegrationHandlerWithRunner(t, r, 1, fp)
	rec := &spyRecorder{}
	h.outcome.Recorder = rec

	cancel, done, _ := startPush(t, h, "app", "v1")
	<-r.started
	cancel()
	close(r.proceed)
	<-done

	if got := fp.targets(); len(got) != 1 || got[0] != "myreg.azurecr.io/app:v1" {
		t.Errorf("ACR pushes = %v, want one push to myreg.azurecr.io/app:v1", got)
	}
	if len(rec.calls) == 1 && rec.calls[0].decision.InfraError {
		t.Errorf("row detail = %q, want no infra error (publication must not die with the client)", rec.calls[0].decision.ErrorDetail)
	}
}

// TestAbandonedScanFailureNamesTheAbandonment is about what the audit row says when a
// scan fails with no client left. "signal: killed" alone is what made the outage
// unreadable for weeks, so a failure that coincides with a departed client must say so
// — and must still carry the raw error, because after this change a kill is no longer
// the client's doing and misattributing it the other way is just as bad.
func TestAbandonedScanFailureNamesTheAbandonment(t *testing.T) {
	r := newPausingRunner()
	r.failWith = errors.New("signal: killed") // e.g. the kernel's OOM killer picked grype
	h := buildIntegrationHandlerWithRunner(t, r, 1, &ctxPusher{})
	rec := &spyRecorder{}
	h.outcome.Recorder = rec

	cancel, done, _ := startPush(t, h, "app", "v1")
	<-r.started
	cancel()
	close(r.proceed)
	<-done

	if len(rec.calls) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rec.calls))
	}
	detail := rec.calls[0].decision.ErrorDetail
	if !strings.Contains(detail, "client disconnected") {
		t.Errorf("error_detail = %q, want it to say the client had disconnected", detail)
	}
	if !strings.Contains(detail, "signal: killed") {
		t.Errorf("error_detail = %q, want the raw scan error kept", detail)
	}
}

// TestScanOverBudgetSaysItRanOutOfTime separates the two remaining ways a scan dies
// with "signal: killed": the gate's own deadline, and the kernel. Step 5's killed_scan
// detector pages about memory pressure, so a scan Merlin itself killed for running past
// gate_timeout must not arrive looking like an OOM — and must not claim a client left
// when the client is still waiting.
func TestScanOverBudgetSaysItRanOutOfTime(t *testing.T) {
	r := newPausingRunner() // never released; only its context can end the scan
	h := buildIntegrationHandlerWithRunner(t, r, 1, &ctxPusher{}, withGateTimeout(80*time.Millisecond))
	rec := &spyRecorder{}
	h.outcome.Recorder = rec

	_, done, res := startPush(t, h, "app", "v1")
	<-done

	if res.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (fail-closed); body=%s", res.Code, res.Body.String())
	}
	if len(rec.calls) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rec.calls))
	}
	detail := rec.calls[0].decision.ErrorDetail
	if !strings.Contains(detail, "80ms") || !strings.Contains(detail, "budget") {
		t.Errorf("error_detail = %q, want it to name the gate budget it exceeded", detail)
	}
	if strings.Contains(detail, "client disconnected") {
		t.Errorf("error_detail = %q, want no client-disconnect claim: the client was still waiting", detail)
	}
}
