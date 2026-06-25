package audit

import (
	"reflect"
	"testing"
)

func TestSplitStatements(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: "single statement",
			sql:  "CREATE TABLE foo (id INT);",
			want: []string{"CREATE TABLE foo (id INT)"},
		},
		{
			name: "multiple statements",
			sql:  "CREATE TABLE foo (id INT); CREATE TABLE bar (name STRING);",
			want: []string{"CREATE TABLE foo (id INT)", "CREATE TABLE bar (name STRING)"},
		},
		{
			name: "trailing semicolon",
			sql:  "CREATE TABLE foo (id INT);",
			want: []string{"CREATE TABLE foo (id INT)"},
		},
		{
			name: "blank lines and whitespace",
			sql:  "CREATE TABLE foo (id INT);\n\n  \nCREATE TABLE bar (name STRING);  ",
			want: []string{"CREATE TABLE foo (id INT)", "CREATE TABLE bar (name STRING)"},
		},
		{
			name: "empty input",
			sql:  "",
			want: nil,
		},
		{
			name: "only whitespace",
			sql:  "   \n\n  \t  ",
			want: nil,
		},
		{
			name: "no trailing semicolon",
			sql:  "CREATE TABLE foo (id INT)",
			want: []string{"CREATE TABLE foo (id INT)"},
		},
		{
			name: "multiple semicolons",
			sql:  "CREATE TABLE foo (id INT);;; CREATE TABLE bar (name STRING)",
			want: []string{"CREATE TABLE foo (id INT)", "CREATE TABLE bar (name STRING)"},
		},
		{
			name: "real schema.sql snippet",
			sql: `CREATE TABLE IF NOT EXISTS gate_decisions (
    ts DateTime64(3)
) ENGINE = MergeTree ORDER BY ts;

ALTER TABLE gate_decisions ADD INDEX IF NOT EXISTS idx_identity (identity) TYPE bloom_filter GRANULARITY 4;`,
			want: []string{
				"CREATE TABLE IF NOT EXISTS gate_decisions (\n    ts DateTime64(3)\n) ENGINE = MergeTree ORDER BY ts",
				"ALTER TABLE gate_decisions ADD INDEX IF NOT EXISTS idx_identity (identity) TYPE bloom_filter GRANULARITY 4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitStatements(tt.sql)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitStatements() = %v, want %v", got, tt.want)
			}
		})
	}
}
