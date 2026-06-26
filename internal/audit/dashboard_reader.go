package audit

import (
	"context"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

// DecisionSummary is one row in the live feed / recent-activity list.
type DecisionSummary struct {
	Ts       time.Time
	PushID   string
	Repo     string
	Tag      string
	Digest   string
	Identity string
	Passed   bool
	Reasons  []string
}

// LatencyPercentiles holds scan-duration percentiles in milliseconds.
type LatencyPercentiles struct {
	P50, P95, P99 float64
}

// DecisionStats aggregates gate decisions over a time window.
type DecisionStats struct {
	Total         uint64
	Passed        uint64
	Rejected      uint64
	Latency       LatencyPercentiles
	RejectReasons []LabeledCount // top reject reasons by frequency
}

// LabeledCount is a generic (label, count) pair used by several aggregates.
type LabeledCount struct {
	Label string
	Count uint64
}

// DecisionHeader is the report header (verdict + provenance) for one image.
type DecisionHeader struct {
	Found          bool
	PushID         string
	Repo           string
	Tag            string
	Digest         string
	Identity       string
	Passed         bool
	FailedPolicies []string
	Reasons        []string
	BaseImageID    string
	TrivyDBVersion string
	Ts             time.Time
}

// ImageRow is one gated image (one push) with its severity tallies.
type ImageRow struct {
	Ts       time.Time
	PushID   string
	Repo     string
	Tag      string
	Digest   string
	Identity string
	Passed   bool
	Crit     uint64
	High     uint64
	Med      uint64
	Low      uint64
}

// ImageFilter narrows the images page. Text matches repo/tag/identity (substring).
type ImageFilter struct {
	Text         string
	HasCritical  bool
	RejectedOnly bool
}

// ImagePage is one page of images plus the total matching count (for pagination).
type ImagePage struct {
	Rows  []ImageRow
	Total uint64
}

// DashboardReader is the read surface the dashboard data service depends on.
// `since` bounds each query to a time window; `limit` caps row counts.
type DashboardReader interface {
	RecentDecisions(ctx context.Context, limit int) ([]DecisionSummary, error)
	DecisionStatsSince(ctx context.Context, since time.Time) (DecisionStats, error)
	DecisionHeaderByRef(ctx context.Context, repo, ref string) (DecisionHeader, error)
	DecisionHeaderByPush(ctx context.Context, pushID string) (DecisionHeader, error)
	FindingsByPush(ctx context.Context, pushID string) ([]policy.Finding, error)
	FindingsByImageRef(ctx context.Context, repo, ref string) ([]policy.Finding, error)
	ImagesPage(ctx context.Context, since time.Time, f ImageFilter, limit, offset int) (ImagePage, error)
}
