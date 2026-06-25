package router

import (
	"strings"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

func TestSummarizeReject(t *testing.T) {
	res := policy.Result{
		Passed: false,
		Verdicts: map[string]policy.Verdict{
			"trivy": {
				Passed:  false,
				Reasons: []string{"CVE-1 (CRITICAL) in openssl 1.1.1", "CVE-2 (CRITICAL) in glibc 2.31"},
			},
			"baseimage": {
				Passed:  false,
				Reasons: []string{"base image not permitted: detected \"alpine\", allowed: rhel(ubi), wolfi/chainguard"},
			},
		},
		Findings: []policy.Finding{
			{CVE: "CVE-1", Severity: "CRITICAL", Pkg: "openssl"},
			{CVE: "CVE-2", Severity: "CRITICAL", Pkg: "glibc"},
		},
	}
	got := SummarizeResult(res)
	if !strings.Contains(got, "CVE-1 (CRITICAL)") {
		t.Errorf("summary must include CVE-1, got %q", got)
	}
	if !strings.Contains(got, "base image not permitted") {
		t.Errorf("summary must include base-image reason, got %q", got)
	}
}

func TestSummarizeBaseImageOnlyReject(t *testing.T) {
	res := policy.Result{
		Passed: false,
		Verdicts: map[string]policy.Verdict{
			"baseimage": {Passed: false, Reasons: []string{"base image not permitted: detected \"alpine\", allowed: rhel(ubi), wolfi/chainguard"}},
			"trivy":     {Passed: true},
		},
	}
	got := SummarizeResult(res)
	if !strings.Contains(got, "base image not permitted") {
		t.Errorf("summary must include the base-image reason, got %q", got)
	}
	if strings.Contains(got, "0 CRITICAL") {
		t.Errorf("must not render a misleading CRITICAL count, got %q", got)
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
