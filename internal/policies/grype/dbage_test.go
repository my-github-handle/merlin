package grype

import (
	"context"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

type spyDBAge struct{ days []float64 }

func (s *spyDBAge) SetScannerDBAgeDays(d float64) { s.days = append(s.days, d) }

func TestParseReportKeepsDBBuiltTimestamp(t *testing.T) {
	raw := []byte(`{"matches":[],"descriptor":{"db":{"status":{"schemaVersion":"v6.1.9","built":"2026-07-17T06:00:00Z"}}}}`)
	rep, err := ParseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC)
	if !rep.DBBuilt.Equal(want) {
		t.Errorf("DBBuilt = %v, want %v", rep.DBBuilt, want)
	}
	// The formatted string stays the audit-facing value; the timestamp is additive.
	if rep.DBVersion != "schema v6.1.9 built 2026-07-17T06:00:00Z" {
		t.Errorf("DBVersion = %q, want the unchanged formatted form", rep.DBVersion)
	}
}

// TestParseReportTolerAtesUnparseableBuilt keeps a scan working when the timestamp
// format changes: a report whose age cannot be derived is still a valid scan, and
// failing it would mean rejecting the push (the gate is fail-closed).
func TestParseReportToleratesUnparseableBuilt(t *testing.T) {
	for _, built := range []string{`""`, `"not-a-time"`, `"2026-07-17 06:00:00 +0000 UTC"`} {
		raw := []byte(`{"matches":[],"descriptor":{"db":{"status":{"schemaVersion":"v6","built":` + built + `}}}}`)
		rep, err := ParseReport(raw)
		if err != nil {
			t.Fatalf("built=%s: %v", built, err)
		}
		if !rep.DBBuilt.IsZero() {
			t.Errorf("built=%s: DBBuilt = %v, want zero", built, rep.DBBuilt)
		}
	}
}

// TestEvaluateObservesDBAge is the point of the whole change: merlin_scanner_db_age_days
// was registered and rendered on the dashboard but nothing ever set it, so a stale
// vulnerability DB — a scanner that passes images because it no longer knows about
// the CVEs — read as "0 days old", the healthiest possible value.
func TestEvaluateObservesDBAge(t *testing.T) {
	built := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC) // 2.5 days later
	sink := &spyDBAge{}
	p := New(
		fakeRunner{report: Report{DBVersion: "schema 5", DBBuilt: built}},
		"CRITICAL",
		WithDBAgeObserver(sink),
		withClock(func() time.Time { return now }),
	)

	if _, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"}); err != nil {
		t.Fatal(err)
	}
	if len(sink.days) != 1 || sink.days[0] != 2.5 {
		t.Errorf("SetScannerDBAgeDays = %v, want [2.5]", sink.days)
	}
}

// TestEvaluateSkipsDBAgeWhenUnknown pins that an unknown build time leaves the
// gauge ALONE rather than writing zero: zero is the healthiest value the gauge can
// hold, so publishing it on missing data would actively hide a stale DB.
func TestEvaluateSkipsDBAgeWhenUnknown(t *testing.T) {
	sink := &spyDBAge{}
	p := New(
		fakeRunner{report: Report{DBVersion: "schema 5"}}, // DBBuilt zero
		"CRITICAL",
		WithDBAgeObserver(sink),
	)

	if _, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"}); err != nil {
		t.Fatal(err)
	}
	if len(sink.days) != 0 {
		t.Errorf("SetScannerDBAgeDays = %v, want no observation for an unknown build time", sink.days)
	}
}

// TestEvaluateClampsFutureDBBuild guards against a clock skew between the pod and
// whatever built the DB producing a negative age, which would render as a
// nonsensical gauge and break any "older than N days" alert.
func TestEvaluateClampsFutureDBBuild(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	sink := &spyDBAge{}
	p := New(
		fakeRunner{report: Report{DBBuilt: now.Add(2 * time.Hour)}},
		"CRITICAL",
		WithDBAgeObserver(sink),
		withClock(func() time.Time { return now }),
	)

	if _, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"}); err != nil {
		t.Fatal(err)
	}
	if len(sink.days) != 1 || sink.days[0] != 0 {
		t.Errorf("SetScannerDBAgeDays = %v, want [0] for a future build time", sink.days)
	}
}

// TestEvaluateWithoutDBAgeObserverIsSafe: the observer is optional, and a nil one
// must not panic a scan — a panic here rejects the push.
func TestEvaluateWithoutDBAgeObserverIsSafe(t *testing.T) {
	p := New(fakeRunner{report: Report{DBBuilt: time.Now()}}, "CRITICAL")
	if _, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"}); err != nil {
		t.Fatal(err)
	}
	p = New(fakeRunner{report: Report{DBBuilt: time.Now()}}, "CRITICAL", WithDBAgeObserver(nil))
	if _, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"}); err != nil {
		t.Fatal(err)
	}
}
