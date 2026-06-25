package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
)

// dockerManifest is a minimal struct to extract referenced digests from a Docker/OCI manifest.
type dockerManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
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
func (h *Handler) handleManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse repo and ref from path: /v2/<repo>/manifests/<ref>
	repo, ref := parseManifestPath(r.URL.Path)
	if repo == "" || ref == "" {
		http.Error(w, "invalid manifest path", http.StatusBadRequest)
		return
	}

	// Get validated identity
	identity, ok := h.validatedIdentity(r)
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

	// Parse manifest to extract referenced digests
	var manifest dockerManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		http.Error(w, fmt.Sprintf("invalid manifest JSON: %v", err), http.StatusBadRequest)
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
	defer h.store.Cleanup(ctx, mr, scratchDir)

	img, err := h.store.Assemble(ctx, mr, scratchDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("assemble image: %v", err), http.StatusInternalServerError)
		return
	}

	// Build gate request
	target := h.registry + "/" + repo + ":" + ref
	req := router.GateRequest{
		Source:   "docker",
		Identity: identity.Subject,
		Image:    img,
		Target:   target,
	}

	// Gate via pool or direct router. The gate returns the result (and any infra
	// error) request-locally; the handler then builds the Decision via the Outcome.
	var (
		res     policy.Result
		gateErr error
	)
	if h.pool != nil {
		timeout := h.gateTimeout
		if timeout == 0 {
			timeout = 5 * time.Minute // default
		}
		gctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		res, gateErr = h.pool.Gate(gctx, req)
	} else {
		res, gateErr = h.router.Gate(ctx, req)
	}

	// Handle ErrSaturated → 503 (before the Outcome runs)
	if errors.Is(gateErr, router.ErrSaturated) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "scan pool saturated, retry later", http.StatusServiceUnavailable)
		return
	}

	// Build the Decision from the gate result. Other infra errors are rendered as
	// 500/502 by Apply. An ACR push failure surfaces as a returned error (502);
	// the Decision still carries the right status to render. Log the infra error so
	// an operator can diagnose a 500/502 (the client only sees a terse summary).
	d, applyErr := h.outcome.Apply(ctx, req, res, gateErr)
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
