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

// CVECount is a top-CVE row.
type CVECount struct {
	CVE          string
	Severity     string
	Pkg          string
	FixedVersion string
	ImageCount   uint64 // distinct image digests affected
}

// SeverityTotals counts findings by severity over a window.
type SeverityTotals struct {
	Critical, High, Medium, Low, Unknown uint64
}

// FixAvailability reports remediation gap: of findings at each severity, how many
// have a non-empty fixed_version.
type FixAvailability struct {
	BySeverity []FixAvailabilityRow
	TopFixable []CVECount // highest-impact CVEs that have a fix available
}

type FixAvailabilityRow struct {
	Severity string
	Total    uint64
	Fixable  uint64 // fixed_version != ''
}

// BaseImageStat is one base image's usage + pass rate.
type BaseImageStat struct {
	BaseImageID string
	Total       uint64
	Passed      uint64
}

// IdentityStat / RepoStat are pass/reject breakdowns per identity or repo.
type IdentityStat struct {
	Identity string
	Total    uint64
	Passed   uint64
}

type RepoStat struct {
	Repo   string
	Total  uint64
	Passed uint64
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

// DashboardReader is the read surface the dashboard data service depends on.
// `since` bounds each query to a time window; `limit` caps row counts.
type DashboardReader interface {
	RecentDecisions(ctx context.Context, limit int) ([]DecisionSummary, error)
	DecisionStatsSince(ctx context.Context, since time.Time) (DecisionStats, error)
	TopCVEs(ctx context.Context, since time.Time, limit int) ([]CVECount, error)
	TopPackages(ctx context.Context, since time.Time, limit int) ([]LabeledCount, error)
	SeverityTotalsSince(ctx context.Context, since time.Time) (SeverityTotals, error)
	FixAvailabilitySince(ctx context.Context, since time.Time, limit int) (FixAvailability, error)
	BaseImagePosture(ctx context.Context, since time.Time) ([]BaseImageStat, error)
	ByIdentity(ctx context.Context, since time.Time, limit int) ([]IdentityStat, error)
	ByRepo(ctx context.Context, since time.Time, limit int) ([]RepoStat, error)
	DecisionHeaderByRef(ctx context.Context, repo, ref string) (DecisionHeader, error)
	DecisionHeaderByPush(ctx context.Context, pushID string) (DecisionHeader, error)
	FindingsByPush(ctx context.Context, pushID string) ([]policy.Finding, error)
	FindingsByImageRef(ctx context.Context, repo, ref string) ([]policy.Finding, error)
}
