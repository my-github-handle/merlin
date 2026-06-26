package audit

import "fmt"

// ttlStatements returns idempotent ALTER TABLE ... MODIFY TTL statements that
// expire rows `retentionDays` after their `ts`. Applied to both audit tables so
// a gate decision and its findings age out together (a decision never points at
// deleted findings). MODIFY TTL is safe to run repeatedly.
func ttlStatements(retentionDays int) []string {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	tables := []string{"gate_decisions", "vulnerability_findings"}
	stmts := make([]string, 0, len(tables))
	for _, tbl := range tables {
		stmts = append(stmts, fmt.Sprintf(
			"ALTER TABLE %s MODIFY TTL ts + INTERVAL %d DAY", tbl, retentionDays))
	}
	return stmts
}
