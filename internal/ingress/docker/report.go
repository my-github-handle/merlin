package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// ReportSource returns the findings for a push (backed by the audit store).
type ReportSource interface {
	FindingsByPush(ctx context.Context, pushID string) ([]policy.Finding, error)
}

func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(w, r) {
		return
	}
	pushID := strings.TrimPrefix(r.URL.Path, "/reports/")
	if pushID == "" || h.reports == nil {
		http.NotFound(w, r)
		return
	}
	findings, err := h.reports.FindingsByPush(r.Context(), pushID)
	if err != nil {
		http.Error(w, "report unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(findings)
}
