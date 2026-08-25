package dashboard

import (
	"sort"
	"strings"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
)

// Turning audit rows into view models is separated from fetching them (data.go) because
// the two fail in unrelated ways and only one of them needs a backend to test. Everything
// here is a pure function of its arguments: no Service receiver, no context, no clock.

// toStatsVM converts a decision aggregate into the summary the templates read.
func toStatsVM(st audit.DecisionStats) StatsVM {
	vm := StatsVM{
		Total: st.Total, Passed: st.Passed, Rejected: st.Rejected,
		PassRate: PassRate(st.Passed, st.Total),
		P50:      st.Latency.P50, P95: st.Latency.P95, P99: st.Latency.P99,
	}
	for _, rr := range st.RejectReasons {
		// Share of REJECTIONS, not of pushes: "75% of rejections were critical CVEs" is
		// the question the panel answers. Dividing by Total instead yields a smaller
		// number that still looks like a plausible answer to a different question.
		vm.RejectReasons = append(vm.RejectReasons, LabeledVM{
			Label: rr.Label, Count: rr.Count, Pct: pct(float64(rr.Count), float64(st.Rejected)),
		})
	}
	return vm
}

// newReportVM assembles a found report from its header and findings.
func newReportVM(hdr audit.DecisionHeader, findings []policy.Finding) ReportVM {
	vm := ReportVM{
		Found: true, PushID: hdr.PushID, Repo: hdr.Repo, Tag: hdr.Tag, Digest: hdr.Digest,
		Identity: hdr.Identity, Passed: hdr.Passed, FailedPolicies: hdr.FailedPolicies,
		Reasons: hdr.Reasons, BaseImageID: hdr.BaseImageID, ScannerDBVersion: hdr.ScannerDBVersion, Ts: hdr.Ts,
		InfraError: hdr.InfraError, ErrorDetail: hdr.ErrorDetail,
	}
	// Age fields are only meaningful together: an unknown created-date must not render as
	// a 0-day-old image that trivially passes the threshold.
	vm.ImageAgeKnown = hdr.ImageAgeKnown
	if vm.ImageAgeKnown {
		vm.ImageCreated = hdr.ImageCreated
		vm.ImageAgeDays = int(hdr.ImageAgeDays)
		vm.AgeThreshold = int(hdr.ImageAgeThresholdDays)
		vm.AgeCompliant = int(hdr.ImageAgeDays) <= int(hdr.ImageAgeThresholdDays)
	}
	vm.Findings, vm.Counts = findingVMs(findings)
	return vm
}

// findingVMs converts findings to view models, counts them by severity, and orders them
// severity-descending then CVE-ascending. Counting and ordering share one pass over the
// same slice, which is the only reason they belong in one function.
func findingVMs(findings []policy.Finding) ([]FindingVM, SeverityVM) {
	var (
		out    []FindingVM
		counts SeverityVM
	)
	for _, f := range findings {
		out = append(out, FindingVM{
			CVE: f.CVE, Severity: f.Severity, Pkg: f.Pkg, Version: f.Version, FixedVersion: f.FixedVersion})
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			counts.Critical++
		case "HIGH":
			counts.High++
		case "MEDIUM":
			counts.Medium++
		case "LOW":
			counts.Low++
		default:
			counts.Unknown++
		}
	}
	// Stable, and by CVE within a severity: the report is linked to from audit records, so
	// the same push must render the same order every time it is opened.
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := sevRank(out[i].Severity), sevRank(out[j].Severity)
		if si != sj {
			return si > sj
		}
		return out[i].CVE < out[j].CVE
	})
	return out, counts
}

// sevRank orders severities for display. An unrecognised severity ranks LAST rather than
// first: it is the scanner reporting something we do not model, not a new worst case.
func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
