package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/promote"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
	"github.com/merlin-gate/merlin/internal/tenant"
)

// forwardManifest pushes a non-filesystem manifest (image index or attestation) to
// ACR verbatim, preserving its exact bytes so its content digest is unchanged. The
// target ref mirrors how the client addressed it: by digest (sub-manifests, e.g. the
// attestation) or by tag (the index). On success it echoes Docker-Content-Digest so
// the docker client accepts the response.
func (h *Handler) forwardManifest(w http.ResponseWriter, ctx context.Context, t *tenant.Tenant, repo, ref string, raw []byte, m parsedManifest, kind manifestKind) {
	digest := manifestDigest(raw)

	// Address the manifest in ACR exactly as the client addressed it here: a
	// digest ref (sha256:...) pushes by digest; anything else is a tag.
	repoRef := t.Registry + "/" + repo
	target := targetRef(t.Registry, repo, ref)

	// An attestation manifest references its own blobs (config + in-toto layers)
	// that Merlin staged but never forwarded; the registry rejects the manifest
	// (MANIFEST_BLOB_UNKNOWN) unless they exist there first. Seed them now. (An
	// index references only sub-manifests, already in ACR from the gated image, so
	// it needs no blob seeding.)
	if kind == kindAttestation {
		if err := h.seedAttestationBlobs(ctx, t, repoRef, m); err != nil {
			log.Printf("forward attestation %s: seed blobs failed: %v", digest, err)
			http.Error(w, fmt.Sprintf("manifest not published: %v", err), http.StatusBadRequest)
			return
		}
	}

	err := t.Pusher.PushManifest(ctx, raw, m.MediaType, target)
	if err != nil && kind == kindIndex {
		// The index's references may simply not have landed yet: publication is
		// asynchronous, so the image it names is enqueued rather than in ACR. Wait for
		// it. Scoped to kindIndex because an attestation's references are the blobs
		// seeded a few lines above — synchronously, by us — so a miss there is our bug,
		// not a pending promotion.
		err = h.awaitIndexReferences(ctx, t.Pusher, raw, m.MediaType, target, err)
	}
	if err != nil {
		// An index whose gated image was rejected has no sub-manifest in ACR, so
		// this PUT fails — that is the gate holding, not an internal fault. Surface
		// it as a 400 so the push fails cleanly with the reason.
		log.Printf("forward %s manifest %s -> %s failed: %v", kindName(kind), digest, target, err)
		http.Error(w, fmt.Sprintf("manifest not published: %v", err), http.StatusBadRequest)
		return
	}
	// A tag-addressed index is the only place the human tag appears in a buildx
	// push (the gated image decision is recorded by digest). Record tag -> digest
	// aliases for every referenced sub-manifest so report lookups by repo:tag can
	// resolve to the gated image's decision. Best-effort: alias loss only degrades
	// by-tag report lookup; by-digest still works.
	if kind == kindIndex && !strings.HasPrefix(ref, "sha256:") {
		if rec, ok := h.tagAliasRecorder(); ok {
			for _, sm := range m.Manifests {
				if sm.Digest == "" {
					continue
				}
				rec.RecordTagAlias(ctx, audit.TagAlias{Repo: repo, Tag: ref, Digest: sm.Digest})
			}
		}
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

const (
	// defaultIndexReferenceWait bounds how long a tag-addressed index forward waits
	// for the image it references to finish promoting to ACR.
	//
	// Sized against what it is waiting for: a promotion is a queue wait plus a
	// re-assemble of the OCI layout from the shared blob store plus the ACR push, so
	// seconds for a small image and tens of seconds for a multi-GB one under a
	// backlog. Not longer, because the wait holds a request open, and a client that
	// gives up is better served by a retry (by then the image IS in ACR, so the retry
	// resolves on the first attempt) than by a connection held past its own timeout.
	defaultIndexReferenceWait = 90 * time.Second
	// defaultIndexReferencePoll is the gap between attempts. Each attempt is one
	// manifest PUT, so this is cheap; keeping it short matters because the common case
	// is a promotion that lands within a second or two of the index arriving.
	defaultIndexReferencePoll = 500 * time.Millisecond
)

func (h *Handler) indexReferenceWait() time.Duration {
	if h.indexWait <= 0 {
		return defaultIndexReferenceWait
	}
	return h.indexWait
}

func (h *Handler) indexReferencePoll() time.Duration {
	if h.indexPoll <= 0 {
		return defaultIndexReferencePoll
	}
	return h.indexPoll
}

// awaitIndexReferences retries an index forward that failed because a manifest it
// references is not in ACR yet, until the reference lands or the wait runs out.
// first is the error the initial attempt already returned.
//
// Why this exists: forwarding an index depends on an ordering that deferring
// publication to a queue silently broke. buildx PUTs the image manifest and then the
// index milliseconds later; while promotion was synchronous the image was in ACR
// before the gate answered 201, so the index always resolved. Once promotion became a
// queue the index arrived first, ACR answered MANIFEST_BLOB_UNKNOWN, and the client's
// whole push failed 400 — with the gated image sitting in ACR UNTAGGED, which is the
// worst of both outcomes: published, unusable, and reported as a failure.
//
// Why waiting does not weaken the gate: a rejected image is never enqueued and never
// promoted, so its reference never appears and the wait ends in the same 400 it would
// have produced immediately. The wait changes how long a rejection takes to report,
// not whether it holds.
func (h *Handler) awaitIndexReferences(ctx context.Context, p acr.Pusher, raw []byte, mediaType, target string, first error) error {
	if !acr.IsMissingReference(first) {
		return first
	}
	deadline := time.Now().Add(h.indexReferenceWait())
	err := first
	for attempts := 1; ; attempts++ {
		if !time.Now().Before(deadline) {
			return fmt.Errorf("index references an image that has not finished publishing after %d attempts over %s (retry the push): %w",
				attempts, h.indexReferenceWait(), err)
		}
		select {
		// The client leaving is the other reason to stop: there is no one left to
		// answer, and the connection's slot is worth more to a push that is still here.
		case <-ctx.Done():
			return fmt.Errorf("index references an image that has not finished publishing, client left: %w", err)
		case <-time.After(h.indexReferencePoll()):
		}
		if err = p.PushManifest(ctx, raw, mediaType, target); err == nil {
			log.Printf("forward index -> %s succeeded after waiting %d attempt(s) for promotion", target, attempts+1)
			return nil
		}
		if !acr.IsMissingReference(err) {
			return err
		}
	}
}

// TagAliasRecorder is optionally implemented by the Outcome's DecisionRecorder
// (audit.Auditor implements it). Optional-interface so recorder fakes keep compiling.
type TagAliasRecorder interface {
	RecordTagAlias(ctx context.Context, alias audit.TagAlias)
}

// tagAliasRecorder returns the outcome's recorder as a TagAliasRecorder when available.
func (h *Handler) tagAliasRecorder() (TagAliasRecorder, bool) {
	if h.outcome == nil || h.outcome.Recorder == nil {
		return nil, false
	}
	rec, ok := h.outcome.Recorder.(TagAliasRecorder)
	return rec, ok
}

// seedAttestationBlobs uploads an attestation manifest's referenced blobs (config
// + layers) from staging to ACR, so the subsequent manifest forward resolves. Each
// blob was staged during the push; it is fetched (digest re-verified) and pushed
// addressed by content digest.
func (h *Handler) seedAttestationBlobs(ctx context.Context, t *tenant.Tenant, repoRef string, m parsedManifest) error {
	type blob struct{ digest, mediaType string }
	var blobs []blob
	if m.Config.Digest != "" {
		blobs = append(blobs, blob{m.Config.Digest, m.Config.MediaType})
	}
	for _, l := range m.Layers {
		blobs = append(blobs, blob{l.Digest, l.MediaType})
	}
	for _, b := range blobs {
		raw, err := h.store.GetStagedBlob(ctx, b.digest)
		if err != nil {
			return fmt.Errorf("fetch staged blob %s: %w", b.digest, err)
		}
		if err := t.Pusher.PushBlob(ctx, raw, b.mediaType, repoRef); err != nil {
			return fmt.Errorf("push blob %s: %w", b.digest, err)
		}
	}
	return nil
}

// kindName renders a manifestKind for logs.
func kindName(k manifestKind) string {
	switch k {
	case kindIndex:
		return "index"
	case kindAttestation:
		return "attestation"
	default:
		return "image"
	}
}

// handleManifest runs the gate on push completion and renders the Decision.
//
// TODO(I-2, staged-blob leak): the early-return 4xx paths below (invalid path,
// auth, read/parse error, ErrIncompletePush) return BEFORE Assemble/Cleanup, so
// any blobs already uploaded under blob/<digest> for this push are never deleted
// and leak in the shared Blob store. Needs a TTL/GC sweep of staged-but-
// unmanifested blobs (a normal client-retry pattern produces these). Tracked for
// post-Phase-6 hardening; do not assume cleanup happens on the reject paths.
//
// TODO(I-3, shared-blob cleanup): staging.Cleanup deletes blobs by content digest,
// so two concurrent pushes sharing a base layer can have one delete a blob the
// other still needs (spurious 500, not a security issue). Needs content-addressed
// ref-counting or TTL-GC instead of per-push deletion. Tracked for hardening.
func (h *Handler) handleManifest(w http.ResponseWriter, r *http.Request, t *tenant.Tenant) {
	ctx := r.Context()

	push, ok := h.readManifestPush(w, r, t)
	if !ok {
		return
	}
	if push.kind == kindIndex || push.kind == kindAttestation {
		h.forwardManifest(w, ctx, t, push.repo, push.ref, push.raw, push.manifest, push.kind)
		return
	}

	// Shed the push if the promotion backlog is already at its bound. This must come
	// BEFORE PutManifest/Assemble: the whole point is to not spend scratch disk (or a
	// scan slot) on an image whose layout would then sit in a queue that is not
	// draining. Only image manifests reach here — index/attestation forwards above
	// hold nothing on disk.
	if h.promotionBacklogFull(r) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "promotion queue saturated", http.StatusServiceUnavailable)
		return
	}

	staged, ok := h.stageImage(ctx, w, push)
	if !ok {
		return
	}
	// Cleanup ownership follows the OCI layout. When promotion is deferred the worker
	// owns the scratch dir and the staged blob refs and will release them after it
	// publishes; deleting them here would delete the layout out from under it and
	// make every promotion fail on a missing directory. pub.handedOff is set ONLY by
	// publication.run, and only after Promote returned nil — an enqueue that failed
	// leaves no owner, so the handler must still clean up.
	//
	// Registered before the gate because every path from here on — a client that
	// disconnects while queued included — must release the staged bytes.
	//
	// Cleanup must run even when the client disconnected: a canceled request ctx
	// would fail the Valkey ref-count decrement AND the blob delete, leaking
	// staged blobs. Detach cancellation but keep values (trace metadata).
	var pub publication
	defer func() {
		if pub.handedOff {
			return
		}
		h.store.Cleanup(context.WithoutCancel(ctx), staged.mr, staged.scratchDir)
	}()

	req := gateRequestFor(t, push, staged)

	// Generate the push ID before the gate: the promotion job, the report URL, and
	// the audit row must all name the same push, and under deferred promotion the
	// report URL goes out in the 201 while the promotion is still queued.
	pushID := h.pushID()

	g := h.runGate(ctx, req)
	if g.abandoned {
		return
	}

	pub = h.publicationFor(t, req, push, staged, pushID)

	// Build the Decision from the gate result. Other infra errors are rendered as
	// 500/502 by Apply. A failed publication surfaces as a returned error (502);
	// the Decision still carries the right status to render.
	d, applyErr := h.outcome.Apply(ctx, pushID, pub.run, req, g.res, g.err, g.scanDur)
	logGateOutcome(req.Target, d, g.err, applyErr)
	writeDecision(w, d, req.Image.Digest)
}

// manifestPush is a manifest PUT, parsed: the bytes exactly as the client sent them,
// what kind of manifest they are, and who pushed them.
type manifestPush struct {
	repo, ref string
	raw       []byte
	manifest  parsedManifest
	kind      manifestKind
	identity  auth.Identity
}

// readManifestPush validates the path and the caller, reads the body under the upload
// bound, and classifies the manifest. ok=false means the request has already been
// answered and the caller must return.
func (h *Handler) readManifestPush(w http.ResponseWriter, r *http.Request, t *tenant.Tenant) (manifestPush, bool) {
	// Parse repo and ref from path: /v2/<repo>/manifests/<ref>
	repo, ref := parseManifestPath(r.URL.Path)
	if repo == "" || ref == "" {
		http.Error(w, "invalid manifest path", http.StatusBadRequest)
		return manifestPush{}, false
	}

	// Get validated identity
	identity, ok := h.validatedIdentity(r, t)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="merlin",service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
		return manifestPush{}, false
	}

	// Read manifest body with size limit
	body := http.MaxBytesReader(w, r.Body, h.getMaxUploadBytes())
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read manifest: %v", err), http.StatusBadRequest)
		return manifestPush{}, false
	}

	// Classify the manifest. A buildx push sends not just the image manifest but
	// also a SLSA attestation manifest (in-toto layers, no filesystem) and an image
	// index referencing both. Those carry nothing scannable, so they are forwarded
	// to ACR verbatim rather than run through the gate (which would tar-extract the
	// non-filesystem layer and 500). The index PUT only succeeds once its referenced
	// image manifest is already in ACR — i.e. only after that image passed the gate —
	// so a rejected image cannot be published by reference.
	manifest, kind, err := classifyManifest(raw)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid manifest JSON: %v", err), http.StatusBadRequest)
		return manifestPush{}, false
	}
	return manifestPush{repo: repo, ref: ref, raw: raw, manifest: manifest, kind: kind, identity: identity}, true
}

// stagedImage is the assembled OCI layout for one push plus the staging refs that own
// the bytes it was built from. Holding one owes a Cleanup to whoever hands it off.
type stagedImage struct {
	mr         staging.ManifestRef
	img        policy.StagedImage
	scratchDir string
}

// stageImage completes the push in the blob store and assembles the OCI layout the
// scanner reads. ok=false means the request has already been answered — and that
// anything this created has already been released, because the caller cannot register
// its cleanup until it holds a stagedImage.
func (h *Handler) stageImage(ctx context.Context, w http.ResponseWriter, push manifestPush) (stagedImage, bool) {
	// Separate the config blob (JSON image config) from the filesystem layers.
	// Only layers are tar+gzip archives to be extracted; the config goes into the
	// OCI layout verbatim. Lumping them together caused Assemble to tar-extract
	// the JSON config and fail with "invalid tar header".
	layerDigests := make([]string, 0, len(push.manifest.Layers))
	for _, layer := range push.manifest.Layers {
		layerDigests = append(layerDigests, layer.Digest)
	}

	// PutManifest checks that all blobs (config + layers) are complete
	mr, err := h.store.PutManifest(ctx, push.repo, push.ref, push.raw, push.manifest.Config.Digest, layerDigests)
	if errors.Is(err, staging.ErrIncompletePush) {
		http.Error(w, "incomplete push: some referenced blobs were not uploaded", http.StatusBadRequest)
		return stagedImage{}, false
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("put manifest: %v", err), http.StatusInternalServerError)
		return stagedImage{}, false
	}

	// Assemble the image
	scratchDir, err := os.MkdirTemp(h.scratchBaseDir, "merlin-assemble-*")
	if err != nil {
		http.Error(w, fmt.Sprintf("create scratch dir: %v", err), http.StatusInternalServerError)
		return stagedImage{}, false
	}

	assembleStart := time.Now()
	img, err := h.store.Assemble(ctx, mr, scratchDir)
	h.observeAssemble(time.Since(assembleStart))
	if err != nil {
		http.Error(w, fmt.Sprintf("assemble image: %v", err), http.StatusInternalServerError)
		// Same detached-cancellation Cleanup the handler would have run: a failed
		// assemble still staged blobs and made a scratch dir, and nobody downstream
		// knows they exist. Answer first, then release — the client's 500 should not
		// wait on a blob-store delete.
		h.store.Cleanup(context.WithoutCancel(ctx), mr, scratchDir)
		return stagedImage{}, false
	}
	return stagedImage{mr: mr, img: img, scratchDir: scratchDir}, true
}

// gateRequestFor builds the gate request for a staged push.
//
// The target must address ACR the same way the client addressed Merlin: by digest
// (buildx pushes the image manifest by digest) or by tag. A digest ref needs "@", not
// ":", or the reference is unparseable.
//
// Assemble cannot fill in Digest — it sees the ManifestRef, not the exact bytes the
// client sent — so this sets it from the canonical manifest digest. Without it every
// audit row records an empty digest, which is both the audit table's sort key and how
// the dashboard identifies an image.
func gateRequestFor(t *tenant.Tenant, push manifestPush, s stagedImage) router.GateRequest {
	img := s.img
	img.Prefix = t.Prefix
	img.Digest = manifestDigest(push.raw)
	return router.GateRequest{
		Source:   "docker",
		Identity: push.identity.Subject,
		Image:    img,
		Target:   targetRef(t.Registry, push.repo, push.ref),
	}
}

// gateRun is one execution of the gate: what it decided, why it could not decide, and
// how long the scan itself took.
type gateRun struct {
	res     policy.Result
	err     error
	scanDur time.Duration
	// abandoned means the client disconnected while queued for a scan slot: nothing
	// was scanned and there is no one left to answer, so no response is written.
	abandoned bool
}

// runGate acquires a scan slot and runs the gate under it, returning the result (and
// any infra error) request-locally so the caller can build the Decision via the
// Outcome.
//
// Slot wait and scan get SEPARATE budgets, from waitContext and scanContext: a slot
// that frees late must still get the full scan window, or queue time silently shrinks
// scans into timeouts. Which context each phase follows is a policy question with two
// different answers, so each is named rather than derived inline here.
func (h *Handler) runGate(reqCtx context.Context, req router.GateRequest) gateRun {
	if h.pool == nil {
		start := time.Now()
		res, err := h.router.Gate(reqCtx, req)
		return gateRun{res: res, err: err, scanDur: time.Since(start)}
	}

	waitCtx, cancelWait := h.waitContext(reqCtx)
	waitStart := time.Now()
	release, aerr := h.pool.Acquire(waitCtx)
	cancelWait()
	// Observe on EVERY path, including both failure paths below. The pushes that
	// exceed the client's 30s response-header ceiling are exactly the ones that
	// fail here, so observing only on success yields survivor bias and makes queue
	// wait look healthy precisely when it is the problem.
	h.observeQueueWait(time.Since(waitStart))
	switch {
	case errors.Is(aerr, router.ErrSaturated):
		// Hand the saturation error to the Outcome so the 503 is recorded and counted
		// like any other incomplete gate.
		return gateRun{err: aerr}
	case aerr != nil:
		// Client disconnected while queued: nothing to scan, no one to answer.
		return gateRun{abandoned: true}
	}
	defer release()

	scanCtx, cancelScan := h.scanContext(reqCtx)
	defer cancelScan()
	start := time.Now()
	res, err := h.pool.Router().Gate(scanCtx, req)
	return gateRun{res: res, err: err, scanDur: time.Since(start)}
}

// defaultGateTimeout budgets one phase of the gate when the operator configured none.
const defaultGateTimeout = 5 * time.Minute

func (h *Handler) gateBudget() time.Duration {
	if h.gateTimeout == 0 {
		return defaultGateTimeout
	}
	return h.gateTimeout
}

// waitContext derives the context a wait for a scan slot runs under. It follows the
// request: a client that has gone away should stop holding a place in the queue, and
// there is nothing yet running to protect.
func (h *Handler) waitContext(reqCtx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(reqCtx, h.gateBudget())
}

// scanContext derives the context the scan itself runs under. Separate from
// waitContext, and named, because the lifetime of a scan that already holds a slot is
// its own question — this is where an answer other than "exactly the request's" goes.
func (h *Handler) scanContext(reqCtx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(reqCtx, h.gateBudget())
}

// publication is what "publish" means for one push, and who owns the staged bytes
// afterwards. Apply does not need to know whether publication is synchronous or
// queued — it renders the same pass/reject/infra outcomes either way.
type publication struct {
	sync     PublishFunc      // synchronous ACR push; used when promoter is nil
	promoter promote.Promoter // non-nil: hand the push off to the worker instead
	job      promote.Job
	// handedOff records that the promotion worker took ownership of the scratch dir
	// and the staged blob refs, so the handler must not clean them up.
	handedOff bool
}

// run publishes the push. It is the PublishFunc the Outcome calls on a pass, so a
// failure here surfaces as the 502 Apply renders.
func (p *publication) run(ctx context.Context) error {
	if p.promoter == nil {
		return p.sync(ctx)
	}
	if err := p.promoter.Promote(ctx, p.job); err != nil {
		return fmt.Errorf("enqueue promotion: %w", err)
	}
	p.handedOff = true // the worker now owns scratchDir and the blob refs
	return nil
}

// publicationFor chooses between an immediate ACR push and a handoff to the promotion
// worker, and assembles the job for the latter. Only the handler's scope holds the
// resolved tenant, the scratch dir and the staged blob digests the worker will need.
func (h *Handler) publicationFor(t *tenant.Tenant, req router.GateRequest, push manifestPush, s stagedImage, pushID string) publication {
	if h.promoter == nil {
		return publication{sync: SyncPublish(t.Pusher, req, h.acrPushObserver())}
	}
	// Every field the worker's Cleanup needs must be carried on the Job: it
	// releases blob ref-counts by ConfigDig + Layers and removes ScratchDir.
	// Omitting any of them leaks the staged blobs and the OCI layout on every push.
	//
	// Ref is how the CLIENT addressed the manifest (tag or sha256:...), not
	// Image.Tag — buildx addresses the image manifest by digest, and targetRef
	// already depends on that distinction. Tag and Digest are carried separately
	// because a promotion that is abandoned is recorded as an audit row, which
	// needs both.
	return publication{
		promoter: h.promoter,
		job: promote.Job{
			PushID:     pushID,
			Tenant:     t.Prefix,
			Repo:       push.repo,
			Tag:        req.Image.Tag,
			Digest:     req.Image.Digest,
			Ref:        push.ref,
			Target:     req.Target,
			OCIPath:    req.Image.OCIPath,
			ScratchDir: s.scratchDir,
			Layers:     s.mr.LayerDigests,
			ConfigDig:  s.mr.ConfigDigest,
			// OCIPath is only meaningful on THIS pod (scratch is a per-pod emptyDir),
			// so the manifest travels with the job: a sibling replica that claims it
			// re-assembles the layout from the shared blob store, and Assemble needs
			// these exact bytes to write index.json.
			Manifest: push.raw,
			Identity: push.identity.Subject,
		},
	}
}

// logGateOutcome puts the cause of a failed push where an operator is already looking:
// the client only ever sees a terse summary.
func logGateOutcome(target string, d Decision, gateErr, applyErr error) {
	if applyErr != nil {
		log.Printf("manifest %s gate outcome infra error: %v", target, applyErr)
		return
	}
	if gateErr != nil {
		// A gate that could not run is rendered as a 500/503 with a NIL applyErr, so
		// the branch above never saw it and the cause reached the audit store only.
		// That made a total scan outage look like unexplained 500s in the log: every
		// push failed, and the reason ("exec grype: no such file or directory") was
		// invisible without querying ClickHouse. The client gets a terse summary by
		// design; the operator needs the cause where they are already looking.
		log.Printf("manifest %s gate did not complete (%d): %v", target, d.StatusCode, gateErr)
	}
}

// writeDecision renders the Decision to the pushing client. digest is the canonical
// manifest digest.
func writeDecision(w http.ResponseWriter, d Decision, digest string) {
	if d.ReportURL != "" {
		w.Header().Set("X-Merlin-Scan-Report-URL", d.ReportURL)
	}
	code := d.StatusCode
	if code == 0 {
		code = http.StatusCreated
	}
	if code == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "5")
	}
	// On success the Docker client requires the canonical manifest digest echoed in
	// Docker-Content-Digest; without it `docker push` fails the manifest commit with
	// "invalid checksum digest format". The digest is over the exact manifest bytes.
	if code >= 200 && code < 300 {
		w.Header().Set("Docker-Content-Digest", digest)
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(d.Summary))
}

// observeAssemble and observeQueueWait record the two phases of the blocked
// manifest-PUT window that happen before the scan and were measured nowhere.
// Both use an optional interface assertion (mirroring Outcome.observePushError)
// rather than widening MetricsObserver, so every existing metrics fake in the
// tests keeps compiling unchanged.
func (h *Handler) observeAssemble(d time.Duration) {
	if h.outcome == nil || h.outcome.Metrics == nil {
		return
	}
	if m, ok := h.outcome.Metrics.(interface{ ObserveAssembleDuration(float64) }); ok {
		m.ObserveAssembleDuration(d.Seconds())
	}
}

// acrPushObserver returns the metrics sink as an ACRPushObserver, or nil when the
// configured sink does not count ACR pushes (hermetic tests). Same optional
// assertion as above, and for the same reason.
func (h *Handler) acrPushObserver() ACRPushObserver {
	if h.outcome == nil || h.outcome.Metrics == nil {
		return nil
	}
	if o, ok := h.outcome.Metrics.(ACRPushObserver); ok {
		return o
	}
	return nil
}

func (h *Handler) observeQueueWait(d time.Duration) {
	if h.outcome == nil || h.outcome.Metrics == nil {
		return
	}
	if m, ok := h.outcome.Metrics.(interface{ ObserveQueueWait(float64) }); ok {
		m.ObserveQueueWait(d.Seconds())
	}
}

// manifestDigest is the canonical content digest of the exact manifest bytes the
// client sent. It identifies the image everywhere: the Docker-Content-Digest the
// client verifies, the audit row's sort key, and the promotion job.
func manifestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// targetRef builds the ACR reference for a manifest, mirroring how the client
// addressed it: a digest ref (sha256:...) uses "@" (by-digest); a tag uses ":".
// Using ":" for a digest produces an unparseable reference (repo:sha256:...).
func targetRef(registry, repo, ref string) string {
	if strings.HasPrefix(ref, "sha256:") {
		return registry + "/" + repo + "@" + ref
	}
	return registry + "/" + repo + ":" + ref
}

// parseManifestPath extracts (repo, ref) from /v2/<repo>/manifests/<ref>
func parseManifestPath(path string) (repo, ref string) {
	path = strings.TrimPrefix(path, "/v2/")
	idx := strings.Index(path, "/manifests/")
	if idx == -1 {
		return "", ""
	}
	repo = path[:idx]
	ref = strings.TrimPrefix(path[idx:], "/manifests/")
	return repo, ref
}
