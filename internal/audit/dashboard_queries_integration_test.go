//go:build integration

package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

// clickhouseTestDSN returns the DSN for integration tests or skips the test if unset.
func clickhouseTestDSN(t *testing.T) string {
	dsn := os.Getenv("MERLIN_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("set MERLIN_CLICKHOUSE_DSN to run")
	}
	return dsn
}

func TestDashboardQueriesRoundTrip(t *testing.T) {
	dsn := clickhouseTestDSN(t)
	w, err := NewClickHouseWriter(dsn, 30)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	defer w.(interface{ Close() error }).Close()
	ctx := context.Background()
	d := Decision{
		PushID: "11111111-1111-1111-1111-111111111111", Repo: "dash/app", Tag: "v1",
		Digest: "sha256:dash", Identity: "tester", Passed: false,
		FailedPolicies: []string{"trivy"}, Reasons: []string{"CRITICAL CVE-2024-0001"},
		BaseImageID: "ubi9", TrivyDBVersion: "v2026-06-25", DurationMS: 4200,
	}
	if err := w.WriteDecision(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFindings(ctx, d, []policy.Finding{
		{CVE: "CVE-2024-0001", Severity: "CRITICAL", Pkg: "openssl", Version: "1.1", FixedVersion: "1.2"},
	}); err != nil {
		t.Fatal(err)
	}

	r, err := NewClickHouseReader(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	since := time.Now().Add(-time.Hour)

	if rec, err := r.RecentDecisions(ctx, 10); err != nil || len(rec) == 0 {
		t.Fatalf("RecentDecisions err=%v n=%d", err, len(rec))
	}
	st, err := r.DecisionStatsSince(ctx, since)
	if err != nil || st.Total == 0 {
		t.Fatalf("DecisionStatsSince err=%v total=%d", err, st.Total)
	}
	if cves, err := r.TopCVEs(ctx, since, 5); err != nil || len(cves) == 0 {
		t.Fatalf("TopCVEs err=%v n=%d", err, len(cves))
	}
	fa, err := r.FixAvailabilitySince(ctx, since, 5)
	if err != nil || len(fa.BySeverity) == 0 {
		t.Fatalf("FixAvailabilitySince err=%v rows=%d", err, len(fa.BySeverity))
	}
	hdr, err := r.DecisionHeaderByRef(ctx, "dash/app", "v1")
	if err != nil || !hdr.Found || hdr.BaseImageID != "ubi9" {
		t.Fatalf("DecisionHeaderByRef err=%v found=%v base=%q", err, hdr.Found, hdr.BaseImageID)
	}
}
