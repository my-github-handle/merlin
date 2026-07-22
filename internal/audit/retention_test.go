package audit

import (
	"strings"
	"testing"
)

func TestTTLStatements(t *testing.T) {
	stmts := ttlStatements(30)
	if len(stmts) != 3 {
		t.Fatalf("got %d statements, want 3 (one per table)", len(stmts))
	}
	joined := strings.Join(stmts, "\n")
	for _, tbl := range []string{"gate_decisions", "vulnerability_findings", "tag_aliases"} {
		if !strings.Contains(joined, tbl) {
			t.Errorf("missing TTL for %s:\n%s", tbl, joined)
		}
	}
	for _, s := range stmts {
		if !strings.Contains(s, "MODIFY TTL") {
			t.Errorf("statement is not a MODIFY TTL: %q", s)
		}
		if !strings.Contains(s, "INTERVAL 30 DAY") {
			t.Errorf("statement does not set 30 day interval: %q", s)
		}
	}
}

func TestTTLStatementsCustomDays(t *testing.T) {
	stmts := ttlStatements(7)
	for _, s := range stmts {
		if !strings.Contains(s, "INTERVAL 7 DAY") {
			t.Errorf("want INTERVAL 7 DAY, got: %q", s)
		}
	}
}
