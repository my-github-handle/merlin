package router

import (
	"strings"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

func TestSummarizeReject(t *testing.T) {
	res := policy.Result{
		Passed: false,
		Findings: []policy.Finding{
			{CVE: "CVE-1", Severity: "CRITICAL", Pkg: "openssl"},
			{CVE: "CVE-2", Severity: "CRITICAL", Pkg: "glibc"},
		},
	}
	got := SummarizeResult(res)
	if !strings.Contains(got, "2 CRITICAL") || !strings.Contains(got, "CVE-1 (openssl)") {
		t.Errorf("summary = %q", got)
	}
}

func TestSummarizePass(t *testing.T) {
	res := policy.Result{
		Passed: true,
		Findings: []policy.Finding{
			{CVE: "CVE-3", Severity: "HIGH", Pkg: "zlib"},
		},
	}
	got := SummarizeResult(res)
	if !strings.Contains(got, "clean") || !strings.Contains(got, "1 HIGH") {
		t.Errorf("summary = %q", got)
	}
}
