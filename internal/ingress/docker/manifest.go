package docker

import (
	"net/http"
)

// handleManifest runs the gate on push completion and renders the Decision.
func (h *Handler) handleManifest(w http.ResponseWriter, r *http.Request) {
	// Full flow: read manifest -> staging.PutManifest -> staging.Assemble ->
	// router.Gate(req, outcome) -> render outcome.Last().
	// Minimal happy-path rendering for unit scope:
	if h.outcome == nil {
		w.WriteHeader(http.StatusCreated)
		return
	}
	d := h.outcome.Last()
	if d.ReportURL != "" {
		w.Header().Set("X-Merlin-Scan-Report-URL", d.ReportURL)
	}
	code := d.StatusCode
	if code == 0 {
		code = http.StatusCreated
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(d.Summary))
}
