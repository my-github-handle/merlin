package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// ReportSource returns the findings for a push (backed by the audit store).
// Reports are addressable two ways: by the opaque push_id, or by the image
// reference the caller pushed (repo:tag or repo@sha256) — the latter is what a
// human at a terminal actually has.
type ReportSource interface {
	FindingsByPush(ctx context.Context, pushID string) ([]policy.Finding, error)
	FindingsByImageRef(ctx context.Context, repo, ref string) ([]policy.Finding, error)
}

func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/reports/")
	if id == "" || h.reports == nil {
		http.NotFound(w, r)
		return
	}

	// The path is either an image reference (repo:tag or repo@sha256 — what the
	// caller pushed) or an opaque push_id. Detect a reference by the "@" digest
	// separator or a ":" tag separator AFTER the last "/" (so a digest's own
	// "sha256:" prefix in repo@sha256:... isn't mistaken for a tag).
	var (
		findings []policy.Finding
		err      error
	)
	if repo, ref, ok := splitImageRef(id); ok {
		findings, err = h.reports.FindingsByImageRef(r.Context(), repo, ref)
	} else {
		findings, err = h.reports.FindingsByPush(r.Context(), id)
	}
	if err != nil {
		http.Error(w, "report unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(findings)
}

// splitImageRef parses an image reference into (repo, ref) where ref is a tag or a
// "sha256:..." digest. Returns ok=false when id is not an image reference (no "@"
// and no ":" in the final path segment) — i.e. it should be treated as a push_id.
//
//	"app:v1"                 -> ("app", "v1", true)
//	"e2e/app:2.13"           -> ("e2e/app", "2.13", true)
//	"app@sha256:abc"         -> ("app", "sha256:abc", true)
//	"88824db0a4604bf4..."    -> ("", "", false)  // push_id
func splitImageRef(id string) (repo, ref string, ok bool) {
	if at := strings.Index(id, "@"); at != -1 {
		return id[:at], id[at+1:], true
	}
	// A tag separator is a ":" in the LAST path segment.
	slash := strings.LastIndex(id, "/")
	lastColon := strings.LastIndex(id, ":")
	if lastColon > slash {
		return id[:lastColon], id[lastColon+1:], true
	}
	return "", "", false
}
