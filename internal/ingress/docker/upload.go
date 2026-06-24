package docker

import "net/http"

// handleUpload implements POST/PATCH/PUT blob upload against the staging store.
func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	// THIN STUB (Phase 4): accepts the upload request without persisting via the
	// staging.Store. This route is auth-gated (see Handler.route), so it is not
	// reachable unauthenticated.
	// TODO(phase5): wire staging.Store (POST begin / PATCH chunk / PUT complete with
	// digest verification) AND enforce request-size/chunk bounds to prevent resource
	// exhaustion before this is production-exposed.
	w.Header().Set("Location", r.URL.Path)
	w.WriteHeader(http.StatusAccepted)
}
