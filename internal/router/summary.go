package router

import (
	"fmt"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// SummarizeResult produces a one-line scan summary for the push response.
func SummarizeResult(res policy.Result) string {
	var crit, high int
	var critItems []string
	for _, f := range res.Findings {
		switch f.Severity {
		case "CRITICAL":
			crit++
			critItems = append(critItems, fmt.Sprintf("%s (%s)", f.CVE, f.Pkg))
		case "HIGH":
			high++
		}
	}
	if !res.Passed {
		return fmt.Sprintf("rejected: %d CRITICAL CVEs — %s", crit, strings.Join(critItems, ", "))
	}
	return fmt.Sprintf("scan clean: %d CRITICAL, %d HIGH", crit, high)
}
