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
	return fmt.Sprintf("scan clean: %d CRITICAL, %d HIGH", crit, high)
}
