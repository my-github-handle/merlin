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

type SeverityVM struct{ Critical, High, Medium, Low, Unknown uint64 }

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

// ImageVM is one row in the Overview images table.
type ImageVM struct {
	Ts                        time.Time
	PushID, Repo, Tag, Digest string
	Identity                  string
	Passed                    bool
	Crit, High, Med, Low      uint64
}

// pagination meta shared by Overview + Images.
type PageMeta struct {
	Page    int // 1-based
	PerPage int // 10
	Total   uint64
	HasPrev bool
	HasNext bool
}

// ImagesVM is a page of images for the AJAX/JSON endpoint.
type ImagesVM struct {
	Range  Range
	Images []ImageVM
	PageMeta
	Errored bool
}

// OverviewVM is the single landing page: hero KPIs + first page of images.
type OverviewVM struct {
	Range          Range
	Stats          StatsVM // pass rate + latency (existing)
	TrivyDBAgeDays float64
	ACRPushSuccess float64
	Images         []ImageVM
	PageMeta
	Errored bool
}
