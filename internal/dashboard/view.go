package dashboard

import "time"

// Range is a validated dashboard time window.
type Range string

const (
	Range1d  Range = "1d"
	Range7d  Range = "7d"
	Range30d Range = "30d"
)

// ParseRange maps a query value to a Range and the corresponding `since` instant
// relative to now. Unknown values fall back to 1d.
func ParseRange(s string, now time.Time) (Range, time.Time) {
	switch s {
	case "7d":
		return Range7d, now.Add(-7 * 24 * time.Hour)
	case "30d":
		return Range30d, now.Add(-30 * 24 * time.Hour)
	default:
		return Range1d, now.Add(-24 * time.Hour)
	}
}

// PassRate returns passed/total as a percentage (0 when total is 0).
func PassRate(passed, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(passed) / float64(total) * 100
}

// StatsVM is the computed health/stat summary shared by tabs.
type StatsVM struct {
	Total, Passed, Rejected uint64
	PassRate                float64
	P50, P95, P99           float64
	RejectReasons           []LabeledVM
}

type LabeledVM struct {
	Label string
	Count uint64
	Pct   float64
}

type ActivityVM struct {
	Range   Range
	Stats   StatsVM
	Recent  []DecisionVM
	Errored bool // a backend query failed; render degraded panels
}

type DecisionVM struct {
	Ts                        time.Time
	PushID, Repo, Tag, Digest string
	Identity                  string
	Passed                    bool
	Reasons                   []string
}

// Health KPIs sourced from the Prometheus gatherer + decision stats.
type HealthVM struct {
	Range          Range
	Stats          StatsVM
	TrivyDBAgeDays float64
	ACRPushSuccess float64 // percentage
	PushErrors     uint64  // scans that failed to run (error), distinct from rejects
	BaseImages     []BaseImageVM
	Errored        bool
}

type BaseImageVM struct {
	BaseImageID   string
	Total, Passed uint64
	PassRate      float64
}

type VulnVM struct {
	Range    Range
	Severity SeverityVM
	TopCVEs  []CVEVM
	Fix      FixVM
	Errored  bool
}

type SeverityVM struct{ Critical, High, Medium, Low, Unknown uint64 }

type CVEVM struct {
	CVE, Severity, Pkg, FixedVersion string
	ImageCount                       uint64
}

type FixVM struct {
	BySeverity []FixRowVM
	TopFixable []CVEVM
}

type FixRowVM struct {
	Severity       string
	Total, Fixable uint64
	Pct            float64
}

type IdentitiesVM struct {
	Range      Range
	Identities []EntityVM
	Repos      []EntityVM
	Errored    bool
}

type EntityVM struct {
	Name          string
	Total, Passed uint64
	PassRate      float64
}

type ReportVM struct {
	Found                               bool
	PushID, Repo, Tag, Digest, Identity string
	Passed                              bool
	FailedPolicies, Reasons             []string
	BaseImageID, TrivyDBVersion         string
	Ts                                  time.Time
	Findings                            []FindingVM
	Counts                              SeverityVM
}

type FindingVM struct {
	CVE, Severity, Pkg, Version, FixedVersion string
}
