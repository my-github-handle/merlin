package docker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/merlin-gate/merlin/internal/staging"
)

// handleUpload implements POST/PATCH/PUT blob upload against the staging store.
func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodPost:
		// POST /v2/<repo>/blobs/uploads/ → begin upload
		repo := parseUploadRepo(r.URL.Path)
		if repo == "" {
			http.Error(w, "missing repository name", http.StatusBadRequest)
			return
		}
		uploadID, err := h.store.BeginUpload(ctx, repo)
		if err != nil {
			http.Error(w, fmt.Sprintf("begin upload: %v", err), http.StatusInternalServerError)
			return
		}
		// Monolithic upload: POST .../uploads/?digest=<d> with the full blob in the
		// body completes the blob in a single request (common in docker/buildkit/
		// containerd clients). Without this the blob is silently never stored and the
		// later manifest PUT fails to assemble.
		if digest := r.URL.Query().Get("digest"); digest != "" {
			// Bytes are about to be buffered: take a slot. Only this branch of POST
			// needs one — a bodiless POST just mints an ID and costs no memory.
			release, ok := h.acquireUploadSlot(w, r)
			if !ok {
				// Shed or disconnected. The ID was minted inside this request, so no
				// client will ever resume it; retire the session instead of stranding it.
				h.abandonUpload(ctx, uploadID)
				return
			}
			defer release()
			body := http.MaxBytesReader(w, r.Body, h.getMaxUploadBytes())
			defer body.Close()
			if err := h.store.CompleteBlob(ctx, uploadID, digest, body); err != nil {
				// Digest mismatch / bad body is a client error. This upload is dead:
				// the client never learned its ID (it was minted inside this request),
				// so nothing will ever resume or complete it. Retire it now or its
				// session state is stranded with no owner.
				h.abandonUpload(ctx, uploadID)
				http.Error(w, fmt.Sprintf("complete blob: %v", err), http.StatusBadRequest)
				return
			}
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, digest))
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusCreated)
			return
		}
		loc := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uploadID)
		w.Header().Set("Location", loc)
		w.Header().Set("Docker-Upload-UUID", uploadID)
		w.Header().Set("Range", "0-0")
		w.WriteHeader(http.StatusAccepted)

	case http.MethodPatch:
		// PATCH /v2/<repo>/blobs/uploads/<uuid> → write chunk
		repo, uuid := parseUploadRef(r.URL.Path)
		if uuid == "" {
			http.Error(w, "missing upload UUID", http.StatusBadRequest)
			return
		}

		// Parse offset from Content-Range header (format: "start-end")
		offset := int64(0)
		if cr := r.Header.Get("Content-Range"); cr != "" {
			parts := strings.Split(cr, "-")
			if len(parts) >= 1 {
				if n, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
					offset = n
				}
			}
		}

		// A chunk write buffers the chunk AND re-reads the accumulated upload, so it
		// must hold a slot. Do NOT abandon the upload on shed/disconnect: the client
		// owns this ID and may legitimately re-PATCH the same offset after a 503.
		release, ok := h.acquireUploadSlot(w, r)
		if !ok {
			return
		}
		defer release()

		// Wrap body with MaxBytesReader
		body := http.MaxBytesReader(w, r.Body, h.getMaxUploadBytes())
		defer body.Close()

		newOffset, err := h.store.WriteChunk(ctx, uuid, offset, body)
		if errors.Is(err, staging.ErrOutOfOrder) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("write chunk: %v", err), http.StatusInternalServerError)
			return
		}

		loc := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uuid)
		w.Header().Set("Location", loc)
		w.Header().Set("Docker-Upload-UUID", uuid)
		w.Header().Set("Range", fmt.Sprintf("0-%d", newOffset-1))
		w.WriteHeader(http.StatusAccepted)

	case http.MethodPut:
		// PUT /v2/<repo>/blobs/uploads/<uuid>?digest=<digest> → complete
		repo, uuid := parseUploadRef(r.URL.Path)
		if uuid == "" {
			http.Error(w, "missing upload UUID", http.StatusBadRequest)
			return
		}

		digest := r.URL.Query().Get("digest")
		if digest == "" {
			http.Error(w, "missing digest query parameter", http.StatusBadRequest)
			return
		}

		// Completion re-reads the whole accumulated upload to verify its digest — the
		// single largest allocation on the push path — so it must hold a slot too. As
		// with PATCH, a shed PUT is retryable by the client: leave the staged bytes.
		release, ok := h.acquireUploadSlot(w, r)
		if !ok {
			return
		}
		defer release()

		// Wrap body with MaxBytesReader (optional final chunk)
		body := http.MaxBytesReader(w, r.Body, h.getMaxUploadBytes())
		defer body.Close()

		err := h.store.CompleteBlob(ctx, uuid, digest, body)
		if err != nil {
			// Assume digest mismatch errors are user errors (400). The upload cannot be
			// salvaged — the digest is committed in the URL, so a retry is a NEW upload —
			// so discard the staged bytes and session rather than leaving them stranded.
			h.abandonUpload(ctx, uuid)
			http.Error(w, fmt.Sprintf("complete blob: %v", err), http.StatusBadRequest)
			return
		}

		loc := fmt.Sprintf("/v2/%s/blobs/%s", repo, digest)
		w.Header().Set("Location", loc)
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// abandonUpload discards a dead upload's staged bytes and session state.
//
// Cancellation is detached: an oversized body or a client disconnect fails
// CompleteBlob with the request ctx ALREADY canceled, which is precisely when the
// cleanup matters most — a canceled ctx would fail both the blob delete and the
// Valkey session delete, leaving exactly the state this call exists to reclaim.
// Best-effort by design: the response is a 400 either way, and a failure here only
// defers reclamation to the key TTL (see staging.DefaultSessionTTL).
func (h *Handler) abandonUpload(ctx context.Context, uploadID string) {
	if err := h.store.AbandonUpload(context.WithoutCancel(ctx), uploadID); err != nil {
		log.Printf("abandon upload %s: %v", uploadID, err)
	}
}

// parseUploadRepo extracts the repository from POST /v2/<repo>/blobs/uploads/
func parseUploadRepo(path string) string {
	// Remove leading /v2/ and trailing /blobs/uploads/
	path = strings.TrimPrefix(path, "/v2/")
	if idx := strings.Index(path, "/blobs/uploads/"); idx != -1 {
		return path[:idx]
	}
	return path
}

// parseUploadRef extracts (repo, uuid) from PATCH/PUT /v2/<repo>/blobs/uploads/<uuid>
func parseUploadRef(path string) (repo, uuid string) {
	path = strings.TrimPrefix(path, "/v2/")
	if idx := strings.Index(path, "/blobs/uploads/"); idx != -1 {
		repo = path[:idx]
		uuid = strings.TrimPrefix(path[idx:], "/blobs/uploads/")
		// Remove query string if present
		if qidx := strings.Index(uuid, "?"); qidx != -1 {
			uuid = uuid[:qidx]
		}
	}
	return
}
