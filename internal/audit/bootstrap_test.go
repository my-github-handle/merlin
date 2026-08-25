package audit

import (
	"strings"
	"testing"
)

// databaseGroup and schemaGroups are the half of bootstrapSchema that de0e3b1 pulled out of
// the connection handling so it could be reached without a ClickHouse. They decide which
// statements run and in what order, which is where the invariants are.

// The bootstrap connection is scoped to "default" and must create the target database by
// name. Getting the name wrong here creates a database nobody writes to and leaves every
// subsequent statement failing against one that does not exist.
func TestDatabaseGroupCreatesTheTargetByNameAndIsRerunnable(t *testing.T) {
	g := databaseGroup("merlin_audit")

	if len(g.stmts) != 1 {
		t.Fatalf("databaseGroup produced %d statements, want exactly 1: %v", len(g.stmts), g.stmts)
	}
	if want := "CREATE DATABASE IF NOT EXISTS merlin_audit"; g.stmts[0] != want {
		t.Errorf("statement = %q, want %q", g.stmts[0], want)
	}
	// The label is what an operator reads when this fails, and the database name is the
	// one fact that failure needs to carry.
	if !strings.Contains(g.label, "merlin_audit") {
		t.Errorf("label %q does not name the database, so a failure does not say which one", g.label)
	}
}

// The order between the two groups is a hard dependency, not a preference: the TTL
// statements are ALTER TABLE ... MODIFY TTL, so running them before the embedded schema has
// created those tables fails outright on a fresh database.
func TestSchemaGroupsPutTheDDLBeforeTheTTLs(t *testing.T) {
	groups := schemaGroups(30)

	if len(groups) != 2 {
		t.Fatalf("schemaGroups returned %d groups, want 2 (schema, then TTLs)", len(groups))
	}
	if got := groups[0].stmts; len(got) == 0 || !strings.Contains(strings.ToUpper(got[0]), "CREATE TABLE") {
		t.Errorf("the first group does not start with a CREATE TABLE, so the TTL ALTERs may run against tables that do not exist yet: %v", got)
	}
	for _, stmt := range groups[1].stmts {
		if !strings.Contains(strings.ToUpper(stmt), "MODIFY TTL") {
			t.Errorf("the second group is meant to be the retention TTLs, got %q", stmt)
		}
	}
}

// The group labels are the only thing distinguishing the two phases in an error, now that
// both run on one connection. Identical labels would make a TTL failure read as a schema
// failure, sending an operator to the wrong file.
func TestSchemaGroupLabelsAreDistinctAndNonEmpty(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range append(schemaGroups(30), databaseGroup("db")) {
		if g.label == "" {
			t.Errorf("a bootstrap group has no label, so its failures say nothing about which phase failed: %v", g.stmts)
		}
		if seen[g.label] {
			t.Errorf("label %q is used by more than one group: a failure in either reads as the other", g.label)
		}
		seen[g.label] = true
	}
}

// retentionDays reaches the TTLs. A dropped argument would silently apply the 30-day default
// to a deployment configured for something else, and the only symptom is rows expiring on
// the wrong schedule — which nobody notices until an audit needs the ones that are gone.
func TestSchemaGroupsForwardRetentionDays(t *testing.T) {
	for _, tc := range []struct {
		days int
		want string
	}{
		{7, "INTERVAL 7 DAY"},
		{90, "INTERVAL 90 DAY"},
		{0, "INTERVAL 30 DAY"},  // ttlStatements' documented default
		{-1, "INTERVAL 30 DAY"}, // a negative retention is not "keep nothing"
	} {
		ttls := schemaGroups(tc.days)[1].stmts
		if len(ttls) == 0 {
			t.Fatalf("schemaGroups(%d) produced no TTL statements", tc.days)
		}
		for _, stmt := range ttls {
			if !strings.Contains(stmt, tc.want) {
				t.Errorf("schemaGroups(%d): %q does not contain %q", tc.days, stmt, tc.want)
			}
		}
	}
}

// An empty or whitespace-only statement is rejected by ClickHouse as "Empty query" (code
// 62), which fails the bootstrap and so fails the pod. splitStatements filters them out of
// the embedded script; this checks nothing reintroduces one on the way to the connection.
func TestNoBootstrapStatementIsEmpty(t *testing.T) {
	var count int
	for _, g := range append(schemaGroups(30), databaseGroup("db")) {
		for _, stmt := range g.stmts {
			if strings.TrimSpace(stmt) == "" {
				t.Errorf("group %q contains an empty statement: ClickHouse rejects it as code 62 and the pod does not boot", g.label)
			}
			count++
		}
	}
	if count < 10 {
		t.Errorf("only %d bootstrap statements found, want at least 10 — the schema is not being read", count)
	}
}
