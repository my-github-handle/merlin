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

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
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
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])

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

	if err := t.Pusher.PushManifest(ctx, raw, m.MediaType, target); err != nil {
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

	// Parse repo and ref from path: /v2/<repo>/manifests/<ref>
	repo, ref := parseManifestPath(r.URL.Path)
	if repo == "" || ref == "" {
		http.Error(w, "invalid manifest path", http.StatusBadRequest)
		return
	}

	// Get validated identity
	identity, ok := h.validatedIdentity(r, t)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="merlin",service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Read manifest body with size limit
	body := http.MaxBytesReader(w, r.Body, h.getMaxUploadBytes())
	defer body.Close()
	manifestBytes, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read manifest: %v", err), http.StatusBadRequest)
		return
	}

	// Classify the manifest. A buildx push sends not just the image manifest but
	// also a SLSA attestation manifest (in-toto layers, no filesystem) and an image
	// index referencing both. Those carry nothing scannable, so they are forwarded
	// to ACR verbatim rather than run through the gate (which would tar-extract the
	// non-filesystem layer and 500). The index PUT only succeeds once its referenced
	// image manifest is already in ACR — i.e. only after that image passed the gate —
	// so a rejected image cannot be published by reference.
	manifest, kind, err := classifyManifest(manifestBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid manifest JSON: %v", err), http.StatusBadRequest)
		return
	}
	if kind == kindIndex || kind == kindAttestation {
		h.forwardManifest(w, ctx, t, repo, ref, manifestBytes, manifest, kind)
		return
	}

	// Separate the config blob (JSON image config) from the filesystem layers.
	// Only layers are tar+gzip archives to be extracted; the config goes into the
	// OCI layout verbatim. Lumping them together caused Assemble to tar-extract
	// the JSON config and fail with "invalid tar header".
	layerDigests := make([]string, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		layerDigests = append(layerDigests, layer.Digest)
	}

	// PutManifest checks that all blobs (config + layers) are complete
	mr, err := h.store.PutManifest(ctx, repo, ref, manifestBytes, manifest.Config.Digest, layerDigests)
	if errors.Is(err, staging.ErrIncompletePush) {
		http.Error(w, "incomplete push: some referenced blobs were not uploaded", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("put manifest: %v", err), http.StatusInternalServerError)
		return
	}

	// Assemble the image
	scratchDir, err := os.MkdirTemp(h.scratchBaseDir, "merlin-assemble-*")
	if err != nil {
		http.Error(w, fmt.Sprintf("create scratch dir: %v", err), http.StatusInternalServerError)
		return
	}
	// Cleanup must run even when the client disconnected: a canceled request ctx
	// would fail the Valkey ref-count decrement AND the blob delete, leaking
	// staged blobs. Detach cancellation but keep values (trace metadata).
	defer h.store.Cleanup(context.WithoutCancel(ctx), mr, scratchDir)

	assembleStart := time.Now()
	img, err := h.store.Assemble(ctx, mr, scratchDir)
	h.observeAssemble(time.Since(assembleStart))
	if err != nil {
		http.Error(w, fmt.Sprintf("assemble image: %v", err), http.StatusInternalServerError)
		return
	}

	// Build gate request. The target must address ACR the same way the client
	// addressed Merlin: by digest (buildx pushes the image manifest by digest) or
	// by tag. A digest ref needs "@", not ":", or the reference is unparseable.
	img.Prefix = t.Prefix
	target := targetRef(t.Registry, repo, ref)
	req := router.GateRequest{
		Source:   "docker",
		Identity: identity.Subject,
		Image:    img,
		Target:   target,
	}

	// Gate via pool or direct router. The gate returns the result (and any infra
	// error) request-locally; the handler then builds the Decision via the Outcome.
	// Slot wait and scan get SEPARATE budgets: a slot that frees late must still
	// get the full scan window, or queue time silently shrinks scans into timeouts.
	var (
		res     policy.Result
		gateErr error
		scanDur time.Duration
	)
	timeout := h.gateTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute // default
	}
	if h.pool != nil {
		waitCtx, cancelWait := context.WithTimeout(ctx, timeout)
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
			// Fall through to the Outcome with the saturation error so the 503 is
			// recorded and counted like any other incomplete gate.
			gateErr = aerr
		case aerr != nil:
			// Client disconnected while queued: nothing to scan, no one to answer.
			return
		default:
			gateStart := time.Now()
			gctx, cancelScan := context.WithTimeout(ctx, timeout)
			res, gateErr = h.pool.Router().Gate(gctx, req)
			cancelScan()
			scanDur = time.Since(gateStart)
			release()
		}
	} else {
		gateStart := time.Now()
		res, gateErr = h.router.Gate(ctx, req)
		scanDur = time.Since(gateStart)
	}

	// Build the Decision from the gate result. Other infra errors are rendered as
	// 500/502 by Apply. An ACR push failure surfaces as a returned error (502);
	// the Decision still carries the right status to render. Log the infra error so
	// an operator can diagnose a 500/502 (the client only sees a terse summary).
	d, applyErr := h.outcome.Apply(ctx, t.Pusher, req, res, gateErr, scanDur)
	if applyErr != nil {
		log.Printf("manifest %s gate outcome infra error: %v", target, applyErr)
	}
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
		sum := sha256.Sum256(manifestBytes)
		w.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(sum[:]))
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

func (h *Handler) observeQueueWait(d time.Duration) {
	if h.outcome == nil || h.outcome.Metrics == nil {
		return
	}
	if m, ok := h.outcome.Metrics.(interface{ ObserveQueueWait(float64) }); ok {
		m.ObserveQueueWait(d.Seconds())
	}
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
