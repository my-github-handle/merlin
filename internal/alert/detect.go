package alert

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Detector names. They are half of the cooldown key and appear verbatim in Slack,
// so they are stable identifiers, not prose.
const (
	DetectorNovelError     = "novel_error"
	DetectorInfraErrorRate = "infra_error_rate"
	DetectorKilledScan     = "killed_scan"
)

// DetailCount is one grouped row of the audit window: a distinct error_detail, how
// many decisions carried it, and when it was first and last seen.
type DetailCount struct {
	Detail      string
	Count       uint64
	First, Last time.Time
}

// Counts is a window's decision total and how many of those were infra errors —
// gate failures, NOT policy rejections. A gate that says "no" to a vulnerable image
// is working; only infra_error=1 means it did not complete.
type Counts struct {
	Total       uint64
	InfraErrors uint64
}

// Rate returns the infra-error share of the window, 0 for an empty window.
func (c Counts) Rate() float64 {
	if c.Total == 0 {
		return 0
	}
	return float64(c.InfraErrors) / float64(c.Total)
}

// Finding is one thing worth telling a human about.
//
// Signature is the grouping key and must NOT contain anything that varies run to
// run (a count, a rate, a timestamp): it is half of the cooldown key, so a
// signature that changes every run means the cooldown never suppresses anything and
// the channel gets the same finding on every tick.
type Finding struct {
	Detector  string
	Signature string
	Summary   string // one line, human-facing
	Count     uint64
	Evidence  string // an example raw error_detail, unnormalized
	FirstSeen time.Time
	LastSeen  time.Time
}

// RateThresholds bounds when a change in the infra-error rate is worth saying.
//
// All three are required together, and each one exists because the other two are
// insufficient on their own:
//   - MinSamples: a 3-push window is 0%, 33% or 67% and means nothing.
//   - MinRate: an absolute floor, or a service that normally never fails alerts
//     whenever a single push does.
//   - MinFactor: a step change, or a steady-state failure rate above the floor
//     alerts on every single run forever.
type RateThresholds struct {
	MinSamples uint64
	MinRate    float64
	MinFactor  float64
}

// NovelErrors reports signatures present in the recent window and absent from the
// baseline window — "something is failing in a way it did not fail before", the
// failure mode a human reading a dashboard genuinely misses.
//
// It returns at most max findings plus the number it dropped. The caller must
// surface the dropped count: a silent cap reads as "that was everything".
func NovelErrors(recent, baseline []DetailCount, max int) ([]Finding, int) {
	known := make(map[string]struct{}, len(baseline))
	for _, b := range baseline {
		if sig := Signature(b.Detail); sig != "" {
			known[sig] = struct{}{}
		}
	}
	grouped := make(map[string]*Finding)
	var order []string
	for _, r := range recent {
		sig := Signature(r.Detail)
		if sig == "" {
			continue
		}
		if _, seen := known[sig]; seen {
			continue
		}
		f, ok := grouped[sig]
		if !ok {
			grouped[sig] = &Finding{
				Detector:  DetectorNovelError,
				Signature: sig,
				Count:     r.Count,
				Evidence:  r.Detail,
				FirstSeen: r.First,
				LastSeen:  r.Last,
			}
			order = append(order, sig)
			continue
		}
		// Same cause reported under several per-push detail strings: one finding.
		f.Count += r.Count
		if r.First.Before(f.FirstSeen) {
			f.FirstSeen = r.First
		}
		if r.Last.After(f.LastSeen) {
			f.LastSeen = r.Last
		}
	}
	out := make([]Finding, 0, len(order))
	for _, sig := range order {
		f := grouped[sig]
		f.Summary = fmt.Sprintf("new failure signature, %d occurrence(s): %s", f.Count, sig)
		out = append(out, *f)
	}
	// Loudest first, so a cap drops the quietest rather than an arbitrary one.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if max > 0 && len(out) > max {
		return out[:max], len(out) - max
	}
	return out, 0
}

// InfraErrorStepChange reports a rise in the share of pushes the gate failed to
// complete. At most one finding: this is a single scalar about the whole service.
func InfraErrorStepChange(recent, baseline Counts, th RateThresholds) []Finding {
	if recent.Total < th.MinSamples {
		return nil
	}
	rate, base := recent.Rate(), baseline.Rate()
	if rate < th.MinRate {
		return nil
	}
	// A clean baseline makes the ratio undefined. Zero to over-the-floor is the
	// clearest step change there is, so it must not be swallowed by the guard.
	if base > 0 && rate < base*th.MinFactor {
		return nil
	}
	return []Finding{{
		Detector: DetectorInfraErrorRate,
		// Fixed string on purpose — see Finding.Signature. The rate lives in Summary.
		Signature: "infra error rate step change",
		Summary: fmt.Sprintf(
			"infra-error rate %.1f%% of %d pushes, up from %.1f%% in the baseline window",
			rate*100, recent.Total, base*100),
		Count: recent.InfraErrors,
	}}
}

// killSignature matches the ways a scan that was killed rather than failed shows up
// in error_detail. "signal: killed" is what os/exec reports for SIGKILL, "137" is
// what a shell-mediated exit reports for the same thing, and grype's own wrapper may
// surface either.
var killSignature = regexp.MustCompile(`signal: (?:killed|SIGKILL)|exit status 137`)

// KilledScans reports scans the kernel (or a memory bound) killed outright.
//
// SCOPE — this catches the grype CHILD being killed, which is exactly what became
// attributable once the per-scan memory bound landed (23593c2). It cannot see the
// merlin PARENT being OOMKilled: a SIGKILL to the parent writes no audit row at all,
// so no query over gate_decisions can find it. Detecting that needs pod state from
// the Kubernetes API — deliberately out of scope here, and the reason this detector
// is named killed_scan rather than oom.
func KilledScans(recent []DetailCount, threshold uint64) []Finding {
	var total uint64
	var evidence string
	var first, last time.Time
	for _, r := range recent {
		if !killSignature.MatchString(r.Detail) {
			continue
		}
		total += r.Count
		if evidence == "" {
			evidence, first, last = r.Detail, r.First, r.Last
			continue
		}
		if r.First.Before(first) {
			first = r.First
		}
		if r.Last.After(last) {
			last = r.Last
		}
	}
	if total == 0 || total < threshold {
		return nil
	}
	return []Finding{{
		Detector: DetectorKilledScan,
		// Fixed string on purpose — see Finding.Signature.
		Signature: "scan killed (SIGKILL/137)",
		Summary: fmt.Sprintf(
			"%d scan(s) killed rather than failed — the per-scan memory bound or the pod cgroup limit is being hit",
			total),
		Count:     total,
		Evidence:  evidence,
		FirstSeen: first,
		LastSeen:  last,
	}}
}
