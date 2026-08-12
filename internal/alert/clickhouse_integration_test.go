//go:build integration

package alert

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
)

// Run with: MERLIN_CLICKHOUSE_DSN=... go test -tags integration ./internal/alert/
func newStore(t *testing.T) (*Store, audit.Writer) {
	t.Helper()
	dsn := os.Getenv("MERLIN_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("set MERLIN_CLICKHOUSE_DSN to run")
	}
	// The audit writer bootstraps gate_decisions; the alert store only adds its own
	// notifications table, exactly as in internal/app.
	w, err := audit.NewClickHouseWriter(dsn, 30)
	if err != nil {
		t.Fatalf("audit writer: %v", err)
	}
	s, err := NewClickHouseStore(dsn)
	if err != nil {
		t.Fatalf("alert store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, w
}

func TestStoreReadsInfraErrorsAndIgnoresPolicyRejections(t *testing.T) {
	s, w := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// One infra error and one POLICY rejection. Only the first is a finding: a gate
	// that rejects a vulnerable image is working.
	infra := audit.Decision{
		PushID: "00000000-0000-0000-0000-0000000000a1", Repo: "alerts-it", Tag: "infra",
		Digest: "sha256:a1", Identity: "it", Passed: false,
		InfraError: true, ErrorDetail: "run grype: signal: killed",
	}
	policyReject := audit.Decision{
		PushID: "00000000-0000-0000-0000-0000000000a2", Repo: "alerts-it", Tag: "policy",
		Digest: "sha256:a2", Identity: "it", Passed: false,
		Reasons: []string{"CVE-2024-1 (CRITICAL) in openssl 1.1.1"},
	}
	for _, d := range []audit.Decision{infra, policyReject} {
		if err := w.WriteDecision(ctx, d); err != nil {
			t.Fatalf("write decision: %v", err)
		}
	}

	since, until := now.Add(-10*time.Minute), now.Add(10*time.Minute)
	details, err := s.InfraErrorDetails(ctx, since, until, 100)
	if err != nil {
		t.Fatalf("InfraErrorDetails: %v", err)
	}
	var killed uint64
	for _, d := range details {
		if d.Detail == "run grype: signal: killed" {
			killed += d.Count
		}
		if d.Detail == "" {
			t.Error("blank error_detail should be filtered in SQL")
		}
	}
	if killed == 0 {
		t.Error("the infra-error decision was not returned")
	}
	if len(KilledScans(details, 1)) != 1 {
		t.Error("KilledScans did not recognise the stored detail")
	}

	counts, err := s.DecisionCounts(ctx, since, until)
	if err != nil {
		t.Fatalf("DecisionCounts: %v", err)
	}
	if counts.Total < 2 {
		t.Errorf("total = %d, want at least the 2 rows just written", counts.Total)
	}
	if counts.InfraErrors < 1 || counts.InfraErrors >= counts.Total {
		t.Errorf("infra errors = %d of %d: the policy rejection must not be counted",
			counts.InfraErrors, counts.Total)
	}
}

func TestStoreCooldownRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	f := Finding{
		Detector: DetectorNovelError, Signature: "integration-test signature",
		Summary: "integration test", Count: 3,
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.RecordNotified(ctx, f, at); err != nil {
		t.Fatalf("RecordNotified: %v", err)
	}
	last, err := s.LastNotified(ctx)
	if err != nil {
		t.Fatalf("LastNotified: %v", err)
	}
	got, ok := last[CooldownKey(f)]
	if !ok {
		t.Fatalf("cooldown key %q not returned", CooldownKey(f))
	}
	if got.Sub(at).Abs() > time.Second {
		t.Errorf("notified_at round-tripped as %s, wrote %s", got, at)
	}

	// A second announcement of the same class must win: the runner compares against
	// the LATEST notification, so an aggregate that returned the older row would
	// suppress forever.
	later := at.Add(time.Hour)
	if err := s.RecordNotified(ctx, f, later); err != nil {
		t.Fatalf("second RecordNotified: %v", err)
	}
	last, err = s.LastNotified(ctx)
	if err != nil {
		t.Fatalf("LastNotified: %v", err)
	}
	if got := last[CooldownKey(f)]; got.Sub(later).Abs() > time.Second {
		t.Errorf("LastNotified returned %s, want the later stamp %s", got, later)
	}
}
