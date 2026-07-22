package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
)

// ReportSource returns the findings for a push (backed by the audit store).
// Reports are addressable two ways: by the opaque push_id, or by the image
// reference the caller pushed (repo:tag or repo@sha256) — the latter is what a
// human at a terminal actually has.
type ReportSource interface {
	FindingsByPush(ctx context.Context, pushID string) ([]policy.Finding, error)
	FindingsByImageRef(ctx context.Context, repo, ref string) ([]policy.Finding, error)
	HeaderByPush(ctx context.Context, pushID string) (audit.DecisionHeader, error)
	HeaderByImageRef(ctx context.Context, repo, ref string) (audit.DecisionHeader, error)
}

// ReportAge is the JSON view of the image-age result in a scan report.
type ReportAge struct {
	Known         bool      `json:"known"`
	Created       time.Time `json:"created"`
	AgeDays       int       `json:"age_days"`
	ThresholdDays int       `json:"threshold_days"`
	Compliant     bool      `json:"compliant"`
}

// reportEnvelope is the GET /reports/<ref> body: the age result (null when the
// age policy was disabled / age unknown) plus the Grype findings. infra_error
// and error mark a push whose gate did NOT complete (scan timeout, assemble or
// ACR failure) — the findings may be empty for that reason, not because the
// image was clean.
type reportEnvelope struct {
	Age        *ReportAge       `json:"age"`
	Findings   []policy.Finding `json:"findings"`
	InfraError bool             `json:"infra_error,omitempty"`
	Error      string           `json:"error,omitempty"`
}

func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request) {
	// Reports authenticate against the tenant that owns the request host; an
	// unknown host is a 404, mirroring the /v2/ surface.
	t, err := h.resolver.ForHost(r.Host)
	if err != nil {
		http.Error(w, "unknown registry", http.StatusNotFound)
		return
	}
	if !h.authenticate(w, r, t) {
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
		hdr      audit.DecisionHeader
	)
	if repo, ref, ok := splitImageRef(id); ok {
		hdr, err = h.reports.HeaderByImageRef(r.Context(), repo, ref)
		if err == nil {
			findings, err = h.reports.FindingsByImageRef(r.Context(), repo, ref)
		}
	} else {
		hdr, err = h.reports.HeaderByPush(r.Context(), id)
		if err == nil {
			findings, err = h.reports.FindingsByPush(r.Context(), id)
		}
	}
	if err != nil {
		// Audit store unreachable / query failed: a retryable 500, deliberately
		// distinct from 404 so an outage is never read as "this image was clean".
		http.Error(w, "report unavailable", http.StatusInternalServerError)
		return
	}
	if !hdr.Found && len(findings) == 0 {
		http.Error(w, "no report for that reference", http.StatusNotFound)
		return
	}

	env := reportEnvelope{Findings: findings}
	if env.Findings == nil {
		env.Findings = []policy.Finding{} // render [], not null (jq-friendly)
	}
	if hdr.Found && hdr.InfraError {
		env.InfraError = true
		env.Error = hdr.ErrorDetail
	}
	if hdr.Found && hdr.ImageAgeKnown {
		env.Age = &ReportAge{
			Known:         true,
			Created:       hdr.ImageCreated,
			AgeDays:       int(hdr.ImageAgeDays),
			ThresholdDays: int(hdr.ImageAgeThresholdDays),
			Compliant:     int(hdr.ImageAgeDays) <= int(hdr.ImageAgeThresholdDays),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
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
