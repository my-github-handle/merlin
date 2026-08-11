package router

import (
	"fmt"
	"sort"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// SummarizeResult produces a one-line scan summary for the push response.
func SummarizeResult(res policy.Result) string {
	var crit, high int
	for _, f := range res.Findings {
		switch f.Severity {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		}
	}
	if !res.Passed {
		// Collect reasons from all failing verdicts
		var reasons []string
		for _, v := range res.Verdicts {
			if !v.Passed {
				reasons = append(reasons, v.Reasons...)
			}
		}
		// Sort for deterministic output
		sort.Strings(reasons)
		if len(reasons) > 0 {
			return fmt.Sprintf("rejected: %s", strings.Join(reasons, "; "))
		}
		return "rejected: image failed policy gate"
	}
	if len(res.Unenforced) > 0 {
		// The image passed only because a policy is in observe mode. Calling this
		// "clean" would report the opposite of the truth to whoever is reading the
		// push output, so name the counts and what went unenforced.
		reasons := append([]string(nil), res.Unenforced...)
		sort.Strings(reasons)
		return fmt.Sprintf("published, gate not enforcing: %d CRITICAL, %d HIGH; %s",
			crit, high, strings.Join(reasons, "; "))
	}
	return fmt.Sprintf("scan clean: %d CRITICAL, %d HIGH", crit, high)
}
