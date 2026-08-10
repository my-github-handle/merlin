// Package audit records gate decisions and findings to an append-only store.
package audit

import (
	"context"
	"errors"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Decision is one gate decision row.
type Decision struct {
	PushID           string
	Repo             string
	Tag              string
	Digest           string
	Identity         string
	Passed           bool
	FailedPolicies   []string
	Reasons          []string
	BaseImageID      string
	ScannerDBVersion string
	DurationMS       uint32

	// Image-age policy result. ImageCreated is zero when age was not determined /
	// the age policy was disabled. ImageAgeKnown explicitly tracks whether age was
	// determined (readers key off this instead of IsZero() to avoid DateTime64 clamping).
	ImageCreated          time.Time
	ImageAgeDays          uint16
	ImageAgeThresholdDays uint16
	ImageAgeKnown         bool

	// InfraError marks a decision where the gate DID NOT COMPLETE (scan timeout,
	// assemble failure, ACR push failure, pool saturation) — distinct from a policy
	// rejection. ErrorDetail carries the operator-facing cause so a failed scan is
	// explainable from the audit store, not only from pod logs.
	InfraError  bool
	ErrorDetail string
}

// Writer persists decisions and findings (e.g. to ClickHouse).
type Writer interface {
	WriteDecision(ctx context.Context, d Decision) error
	WriteFindings(ctx context.Context, d Decision, findings []policy.Finding) error
}

// TagAlias associates a tag with the image digest it referenced, recorded when an
// image index is forwarded by tag (buildx pushes record the gated image by digest).
type TagAlias struct {
	Repo   string
	Tag    string
	Digest string
}

// TagAliasWriter is optionally implemented by a Writer that can persist tag
// aliases. Kept as a separate interface so existing Writer fakes stay valid.
type TagAliasWriter interface {
	WriteTagAlias(ctx context.Context, a TagAlias) error
}

var errQueueFull = errors.New("audit: queue full, decision dropped")
