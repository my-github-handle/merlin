package docker

import (
	"net/http"
)

// handleManifest runs the gate on push completion and renders the Decision.
func (h *Handler) handleManifest(w http.ResponseWriter, r *http.Request) {
	// THIN STUB (Phase 4): renders a pre-set outcome Decision for unit scope.
	//
	// TODO(phase5): wire the full manifest flow:
	//   1. read manifest body + referenced layer digests
	//   2. staging.PutManifest -> staging.Assemble(scratch)
	//   3. gate via *router.Pool.Gate(ctx, GateRequest{...}, outcome)
	//   4. if errors.Is(err, router.ErrSaturated): respond 503 + Retry-After (retryable backpressure)
	//   5. otherwise render outcome.Last() (status + summary + report URL)
	// The router.ErrSaturated -> 503 mapping MUST be added here when Pool.Gate is
	// invoked; it cannot exist until then because ErrSaturated originates from that call.
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
