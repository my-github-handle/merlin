package docker

import "net/http"

// handleUpload implements POST/PATCH/PUT blob upload against the staging store.
func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	// Implemented against staging.Store in the full V2 flow (Phase 5 integration
	// test drives the complete sequence). Minimal accept for now:
	w.Header().Set("Location", r.URL.Path)
	w.WriteHeader(http.StatusAccepted)
}
