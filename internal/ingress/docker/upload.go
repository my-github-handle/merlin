package docker

import (
	"errors"
	"fmt"
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
			body := http.MaxBytesReader(w, r.Body, h.getMaxUploadBytes())
			defer body.Close()
			if err := h.store.CompleteBlob(ctx, uploadID, digest, body); err != nil {
				// Digest mismatch / bad body is a client error.
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

		// Wrap body with MaxBytesReader (optional final chunk)
		body := http.MaxBytesReader(w, r.Body, h.getMaxUploadBytes())
		defer body.Close()

		err := h.store.CompleteBlob(ctx, uuid, digest, body)
		if err != nil {
			// Assume digest mismatch errors are user errors (400)
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
