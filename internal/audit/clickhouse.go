package audit

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/merlin-gate/merlin/internal/policy"
)

//go:embed schema.sql
var schemaSQL string

type clickhouseWriter struct {
	conn driver.Conn
}

// NewClickHouseWriter connects to ClickHouse via a DSN and self-bootstraps the schema.
// The writer creates the target database and schema tables idempotently on first construction.
func NewClickHouseWriter(dsn string) (Writer, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse clickhouse dsn: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	if err := conn.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	// Bootstrap schema: create database + tables idempotently
	if err := bootstrapSchema(opts); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bootstrap schema: %w", err)
	}

	return &clickhouseWriter{conn: conn}, nil
}

// bootstrapSchema creates the target database and schema tables idempotently.
// Uses a separate connection to the "default" database to execute CREATE DATABASE,
// then applies the embedded schema.sql statements. This is safe to call repeatedly.
func bootstrapSchema(opts *clickhouse.Options) error {
	ctx := context.Background()
	targetDB := opts.Auth.Database
	if targetDB == "" {
		return fmt.Errorf("target database not specified in DSN")
	}

	// Create a connection to the "default" database to run CREATE DATABASE.
	// This avoids the issue of connecting to a database that doesn't exist yet.
	bootstrapOpts := *opts
	bootstrapOpts.Auth.Database = "default"
	bootstrapConn, err := clickhouse.Open(&bootstrapOpts)
	if err != nil {
		return fmt.Errorf("open bootstrap connection: %w", err)
	}
	defer bootstrapConn.Close()

	// Create the target database if it doesn't exist
	createDB := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", targetDB)
	if err := bootstrapConn.Exec(ctx, createDB); err != nil {
		return fmt.Errorf("create database %q: %w", targetDB, err)
	}

	// Now connect to the target database and apply the schema
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return fmt.Errorf("open target connection: %w", err)
	}
	defer conn.Close()

	// Split schema.sql into individual statements and execute each
	statements := splitStatements(schemaSQL)
	for _, stmt := range statements {
		if err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("exec schema statement: %w", err)
		}
	}

	return nil
}

// splitStatements splits a SQL script into individual statements on semicolons.
// Filters out empty or whitespace-only statements. Does not handle SQL comments.
func splitStatements(sql string) []string {
	parts := strings.Split(sql, ";")
	var stmts []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		stmts = append(stmts, trimmed)
	}
	return stmts
}

func (c *clickhouseWriter) WriteDecision(ctx context.Context, d Decision) error {
	return c.conn.Exec(ctx, `
INSERT INTO gate_decisions
(ts, push_id, image_repo, image_tag, image_digest, identity, passed, failed_policies, reasons, base_image_id, trivy_db_version, duration_ms)
VALUES (now64(3), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.PushID, d.Repo, d.Tag, d.Digest, d.Identity, d.Passed,
		d.FailedPolicies, d.Reasons, d.BaseImageID, d.TrivyDBVersion, d.DurationMS)
}

func (c *clickhouseWriter) WriteFindings(ctx context.Context, d Decision, findings []policy.Finding) error {
	batch, err := c.conn.PrepareBatch(ctx, `
INSERT INTO vulnerability_findings
(ts, push_id, image_digest, image_repo, cve_id, severity, pkg_name, pkg_version, fixed_version, base_image_id, identity)`)
	if err != nil {
		return fmt.Errorf("prepare findings batch: %w", err)
	}
	for _, f := range findings {
		if err := batch.Append(
			nowFn(), d.PushID, d.Digest, d.Repo,
			f.CVE, f.Severity, f.Pkg, f.Version, f.FixedVersion,
			d.BaseImageID, d.Identity,
		); err != nil {
			return fmt.Errorf("append finding: %w", err)
		}
	}
	return batch.Send()
}

// Close closes the ClickHouse writer connection.
func (c *clickhouseWriter) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Reader runs reverse-lookup queries against ClickHouse.
type Reader struct {
	conn driver.Conn
}

// NewClickHouseReader connects to ClickHouse for read-only queries.
func NewClickHouseReader(dsn string) (*Reader, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse clickhouse dsn: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	if err := conn.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}
	return &Reader{conn: conn}, nil
}

// ImagesByCVE (A): which image digests contained a given CVE.
func (r *Reader) ImagesByCVE(ctx context.Context, cve string) ([]string, error) {
	return r.queryStrings(ctx,
		"SELECT DISTINCT image_digest FROM vulnerability_findings WHERE cve_id = ?", cve)
}

// ImagesByPackage (D): which image digests contain a given package.
func (r *Reader) ImagesByPackage(ctx context.Context, pkg string) ([]string, error) {
	return r.queryStrings(ctx,
		"SELECT DISTINCT image_digest FROM vulnerability_findings WHERE pkg_name = ?", pkg)
}

func (r *Reader) queryStrings(ctx context.Context, q string, arg string) ([]string, error) {
	rows, err := r.conn.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DecisionsByDigest (B) and DecisionsByIdentity (C) return decision rows.
func (r *Reader) DecisionsByDigest(ctx context.Context, digest string) ([]Decision, error) {
	return r.queryDecisions(ctx,
		"SELECT push_id, image_repo, image_tag, image_digest, identity, passed FROM gate_decisions WHERE image_digest = ? ORDER BY ts", digest)
}

func (r *Reader) DecisionsByIdentity(ctx context.Context, identity string) ([]Decision, error) {
	return r.queryDecisions(ctx,
		"SELECT push_id, image_repo, image_tag, image_digest, identity, passed FROM gate_decisions WHERE identity = ? ORDER BY ts", identity)
}

func (r *Reader) queryDecisions(ctx context.Context, q, arg string) ([]Decision, error) {
	rows, err := r.conn.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.PushID, &d.Repo, &d.Tag, &d.Digest, &d.Identity, &d.Passed); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// FindingsByPush serves the scan-report endpoint.
func (r *Reader) FindingsByPush(ctx context.Context, pushID string) ([]policy.Finding, error) {
	rows, err := r.conn.Query(ctx,
		"SELECT cve_id, severity, pkg_name, pkg_version, fixed_version FROM vulnerability_findings WHERE push_id = ?", pushID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []policy.Finding
	for rows.Next() {
		var f policy.Finding
		if err := rows.Scan(&f.CVE, &f.Severity, &f.Pkg, &f.Version, &f.FixedVersion); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Close closes the ClickHouse reader connection.
func (r *Reader) Close() error {
	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}

func nowFn() time.Time { return time.Now() }
