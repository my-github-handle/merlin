// Package alert turns the audit trail into a small number of notifications.
//
// It is deliberately not a detection framework. There is no Source interface, no
// adapter per backend and no incident lifecycle state machine: three queries over
// gate_decisions, three pure predicates over their results, and one timestamp per
// (detector, signature) to stop the same finding being announced every run. The
// residual novel-failure rate this serves is on the order of one event per day, so
// the simple version is the version that fits it. See
// docs/plans/2026-08-11-llm-observability-agent.md §0 step 5.
package alert

import (
	"regexp"
	"strings"
)

// maxSignatureLen caps a signature. It is a ClickHouse ORDER BY key and a line in a
// Slack message, and grype's stderr can be kilobytes, so the cap is what keeps one
// pathological scan from defining the notifications table's row size.
const maxSignatureLen = 200

// The substitutions below run in order. Each one removes something that varies
// PER PUSH while the failure is the same; nothing here may remove a token that
// distinguishes one cause from another (exit status, signal name, HTTP status),
// because that would make a new failure look like an old one — the exact blindness
// the novelty detector exists to remove.
var substitutions = []struct {
	re   *regexp.Regexp
	with string
}{
	// Content-addressed digests: different image, same failure.
	// Unbounded run length, not {7,64}: a truncated or over-long hex tail must still
	// collapse, or one stray character reintroduces per-image signatures.
	{regexp.MustCompile(`sha256:[0-9a-fA-F]{7,}`), "sha256:*"},
	// Push IDs.
	{regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`), "*uuid*"},
	// Per-push scratch and promote dirs (os.MkdirTemp random suffix).
	{regexp.MustCompile(`(merlin-(?:assemble|promote)-)[0-9]+`), "${1}*"},
	// URLs: the HOST is kept (which registry failed is diagnostic) and the path is
	// dropped, because it carries repo, tag and digest.
	{regexp.MustCompile(`(https?://[^/\s]+)(/\S*)?`), "${1}/*"},
	// Retry counts.
	{regexp.MustCompile(`\bafter \d+ attempts?\b`), "after *n* attempts"},
	// Durations.
	{regexp.MustCompile(`\b\d+(\.\d+)?(ns|µs|us|ms|s|m|h)\b`), "*dur*"},
	// Long hex runs that are not digests (blob IDs, request IDs).
	{regexp.MustCompile(`\b[0-9a-fA-F]{12,}\b`), "*hex*"},
	// Byte counts and other large numbers. The threshold is 4+ digits on purpose:
	// exit statuses, signals and HTTP statuses are 1-3 digits and MUST survive.
	{regexp.MustCompile(`\b\d{4,}\b`), "*n*"},
}

var whitespace = regexp.MustCompile(`\s+`)

// Signature reduces one gate_decisions.error_detail to a stable class, so that N
// failures of the same cause group into one finding instead of N.
//
// An empty or blank detail has no signature: a decision with infra_error=1 and no
// detail carries no information to group on, and inventing a bucket for it would
// mean alerting on "something failed, cause unknown" every time one appears.
func Signature(detail string) string {
	s := whitespace.ReplaceAllString(strings.TrimSpace(detail), " ")
	if s == "" {
		return ""
	}
	for _, sub := range substitutions {
		s = sub.re.ReplaceAllString(s, sub.with)
	}
	s = strings.TrimSpace(whitespace.ReplaceAllString(s, " "))
	if len(s) > maxSignatureLen {
		s = strings.TrimSpace(s[:maxSignatureLen])
	}
	return s
}
