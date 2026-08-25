package audit

import (
	"regexp"
	"strings"
	"testing"
)

// schema.sql is applied by bootstrapSchema on EVERY writer construction, which means every
// pod start and every restart. It is also the only place the audit tables are defined, and
// the only artifact that has to serve two different populations at once: a fresh database
// that gets the CREATE TABLEs, and a long-running one that gets the ALTERs. Nothing checked
// any of that — bootstrapSchema is 0.0% hermetically because it needs a live ClickHouse,
// and the DDL went with it.
//
// These tests need no ClickHouse. They read the embedded script through splitStatements,
// which is the same view bootstrapSchema gets, and assert the properties that make the
// script safe to re-run and consistent between the two populations.

var (
	createTableRe = regexp.MustCompile(`(?is)^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`)
	alterTableRe  = regexp.MustCompile(`(?is)^ALTER\s+TABLE\s+(\w+)\s+(.*)$`)
)

// Re-running a non-idempotent statement fails, and since bootstrapSchema runs on every
// start, that failure is not "the migration failed once" — it is a pod that never comes up
// again after its first successful boot, on a gate that fails closed. Every statement must
// therefore be safe the second time.
//
// MODIFY is exempt because it is idempotent by construction: it states the desired type or
// TTL rather than adding something that could already be there.
func TestEverySchemaStatementIsSafeToRunTwice(t *testing.T) {
	for _, stmt := range splitStatements(schemaSQL) {
		upper := strings.ToUpper(stmt)
		switch {
		case strings.Contains(upper, "MODIFY COLUMN"), strings.Contains(upper, "MODIFY TTL"):
			// Declares the end state; running it again is a no-op.
		case !strings.Contains(upper, "IF NOT EXISTS"):
			t.Errorf("statement is not safe to re-run, so the second pod start fails and the gate stays down:\n\t%s",
				firstLine(stmt))
		}
	}
}

// A fresh database gets the CREATE TABLEs; every ALTER below them then runs against a table
// that exists. Move an ALTER above its CREATE and bootstrap fails on a new install only —
// which is the worst shape of bug, because every existing environment keeps working and the
// break surfaces in whichever cluster is stood up next.
func TestTablesAreCreatedBeforeTheyAreAltered(t *testing.T) {
	created := map[string]bool{}
	for _, stmt := range splitStatements(schemaSQL) {
		if m := createTableRe.FindStringSubmatch(stmt); m != nil {
			created[m[1]] = true
			continue
		}
		if m := alterTableRe.FindStringSubmatch(stmt); m != nil {
			if !created[m[1]] {
				t.Errorf("ALTER on %q appears before its CREATE TABLE, so a fresh database fails to bootstrap:\n\t%s",
					m[1], firstLine(stmt))
			}
		}
	}
	if len(created) == 0 {
		t.Fatal("no CREATE TABLE found in schema.sql — this test has stopped reading the schema")
	}
}

// The retention TTL is the compliance story: audit rows expire retentionDays after ts. A
// table created here but missing from ttlStatements keeps its rows FOREVER, and does so
// silently — there is no error, the table simply has no TTL. That is the one failure in this
// file that nothing else would ever surface.
func TestEveryAuditTableHasARetentionTTL(t *testing.T) {
	created := map[string]bool{}
	for _, stmt := range splitStatements(schemaSQL) {
		if m := createTableRe.FindStringSubmatch(stmt); m != nil {
			created[m[1]] = true
		}
	}

	ttled := map[string]bool{}
	for _, stmt := range ttlStatements(30) {
		m := alterTableRe.FindStringSubmatch(stmt)
		if m == nil {
			t.Fatalf("ttlStatements produced something that is not an ALTER TABLE: %q", stmt)
		}
		ttled[m[1]] = true
	}

	for tbl := range created {
		if !ttled[tbl] {
			t.Errorf("table %q has no TTL in ttlStatements: its audit rows are retained forever, silently", tbl)
		}
	}
	for tbl := range ttled {
		if !created[tbl] {
			t.Errorf("ttlStatements alters %q, which schema.sql does not create: bootstrap fails on a fresh database", tbl)
		}
	}
}

// The TTL is "ts + INTERVAL n DAY", so a table without a ts column cannot carry it. This is
// only reachable by adding a table whose time column is named something else, which would
// pass the test above and then fail at bootstrap.
func TestEveryTTLedTableHasATsColumn(t *testing.T) {
	for _, stmt := range splitStatements(schemaSQL) {
		m := createTableRe.FindStringSubmatch(stmt)
		if m == nil {
			continue
		}
		if !regexp.MustCompile(`(?im)^\s*ts\s+DateTime`).MatchString(stmt) {
			t.Errorf("table %q has no ts column, so its retention TTL (ts + INTERVAL n DAY) cannot apply", m[1])
		}
	}
}

// severity is declared twice — inline in the CREATE TABLE for a fresh database, and again in
// a MODIFY COLUMN for databases that predate a value being added (the MODIFY exists because
// Grype emits Negligible). Extending one and not the other gives a fresh install and an
// upgraded install DIFFERENT enums, and the narrower one rejects inserts of the missing
// value: findings silently stop being written for whichever severity is missing.
func TestTheSeverityEnumIsDeclaredIdenticallyInBothPlaces(t *testing.T) {
	enumRe := regexp.MustCompile(`(?is)Enum8\(([^)]*)\)`)
	var inCreate, inModify string
	for _, stmt := range splitStatements(schemaSQL) {
		m := enumRe.FindStringSubmatch(stmt)
		if m == nil {
			continue
		}
		normalised := strings.Join(strings.Fields(m[1]), "")
		if createTableRe.MatchString(stmt) {
			inCreate = normalised
		} else if strings.Contains(strings.ToUpper(stmt), "MODIFY COLUMN") {
			inModify = normalised
		}
	}
	if inCreate == "" || inModify == "" {
		t.Fatalf("expected the severity enum in both a CREATE TABLE and a MODIFY COLUMN, got create=%q modify=%q",
			inCreate, inModify)
	}
	if inCreate != inModify {
		t.Errorf("severity enum differs between a fresh install and an upgraded one:\n\tCREATE: %s\n\tMODIFY: %s\nthe narrower one rejects inserts of the values it lacks",
			inCreate, inModify)
	}
}

// Columns added by an online ALTER also appear inline in the CREATE TABLE, so a fresh
// database gets them without the ALTER. If the two declarations drift, the same column has
// a different type or default depending on when the database was created — and every query
// that reads it behaves differently per environment.
func TestOnlineAddedColumnsMatchTheirInlineDeclaration(t *testing.T) {
	addColRe := regexp.MustCompile(`(?is)^ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+(\w+)\s+(.*)$`)

	creates := map[string]string{}
	var alters [][3]string
	for _, stmt := range splitStatements(schemaSQL) {
		if m := createTableRe.FindStringSubmatch(stmt); m != nil {
			creates[m[1]] = stmt
			continue
		}
		if m := addColRe.FindStringSubmatch(stmt); m != nil {
			alters = append(alters, [3]string{m[1], m[2], strings.Join(strings.Fields(m[3]), " ")})
		}
	}
	if len(alters) == 0 {
		t.Fatal("no ADD COLUMN statements found — this test has stopped reading the schema")
	}

	for _, a := range alters {
		table, col, wantDef := a[0], a[1], a[2]
		body, ok := creates[table]
		if !ok {
			continue // covered by TestTablesAreCreatedBeforeTheyAreAltered
		}
		inline := regexp.MustCompile(`(?im)^\s*` + regexp.QuoteMeta(col) + `\s+(.*?),?\s*$`).FindStringSubmatch(body)
		if inline == nil {
			t.Errorf("%s.%s is added by ALTER but absent from the CREATE TABLE: a fresh database will not have it until the ALTER runs, and every query reading it depends on boot order",
				table, col)
			continue
		}
		gotDef := strings.Join(strings.Fields(inline[1]), " ")
		if !strings.EqualFold(gotDef, wantDef) {
			t.Errorf("%s.%s is declared differently in the two places:\n\tinline: %s\n\tALTER:  %s\nthe column's type or default then depends on when the database was created",
				table, col, gotDef, wantDef)
		}
	}
}

// firstLine keeps multi-statement failure messages to one readable line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i]) + " ..."
	}
	return strings.TrimSpace(s)
}
