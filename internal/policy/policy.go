// Package policy defines the extensible gate engine and its Policy interface.
package policy

import (
	"context"
	"time"
)

// StagedImage is the assembled image a policy evaluates.
type StagedImage struct {
	Repo    string
	Tag     string
	Digest  string
	FSPath  string // assembled root filesystem directory (for os-release reads)
	OCIPath string // on-disk OCI layout (for Trivy)
	// Created is the image config's "created" timestamp (RFC3339). Zero value means
	// the timestamp could not be determined; the image-age policy fails closed on it.
	Created time.Time
	// Prefix is the resolved tenant prefix (set by the ingress handler). The image-age
	// policy uses it to select the per-tenant age rule.
	Prefix string
}

// Verdict is a single policy's decision. Zero value is a fail (Passed=false).
// Findings and ScannerDBVersion carry per-evaluation scan data back to the
// engine so it can be aggregated into Result without any shared policy state.
type Verdict struct {
	Passed           bool
	Reasons          []string
	Findings         []Finding
	ScannerDBVersion string
}

// Finding is one vulnerability detected during scanning.
type Finding struct {
	CVE          string
	Severity     string
	Pkg          string
	Version      string
	FixedVersion string
}

// Policy evaluates a staged image and returns a verdict.
type Policy interface {
	Name() string
	Evaluate(ctx context.Context, img StagedImage) (Verdict, error)
}

// Result is the aggregate outcome of running all policies.
type Result struct {
	Passed         bool
	Verdicts       map[string]Verdict
	Findings       []Finding
	TrivyDBVersion string
}
