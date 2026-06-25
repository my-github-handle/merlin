// Package audit records gate decisions and findings to an append-only store.
package audit

import (
	"context"
	"errors"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Decision is one gate decision row.
type Decision struct {
	PushID         string
	Repo           string
	Tag            string
	Digest         string
	Identity       string
	Passed         bool
	FailedPolicies []string
	Reasons        []string
	BaseImageID    string
	TrivyDBVersion string
	DurationMS     uint32
}

// Writer persists decisions and findings (e.g. to ClickHouse).
type Writer interface {
	WriteDecision(ctx context.Context, d Decision) error
	WriteFindings(ctx context.Context, d Decision, findings []policy.Finding) error
}

var errQueueFull = errors.New("audit: queue full, decision dropped")
