package audit

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
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
// retentionDays sets a TTL on the audit tables (rows expire retentionDays after ts).
func NewClickHouseWriter(dsn string, retentionDays int) (Writer, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse clickhouse dsn: %w", err)
	}
	// Bootstrap FIRST (via a connection scoped to the "default" database): the target
	// database may not exist yet, so opening+pinging a connection scoped to it would
	// fail with "Database <db> does not exist". bootstrapSchema creates the database
	// and the idempotent schema tables before we open the target-scoped connection.
	if err := bootstrapSchema(opts, retentionDays); err != nil {
		return nil, fmt.Errorf("bootstrap schema: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	if err := conn.Ping(context.Background()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	return &clickhouseWriter{conn: conn}, nil
}

// bootstrapSchema creates the target database and schema tables idempotently.
// Uses a separate connection to the "default" database to execute CREATE DATABASE,
// then applies the embedded schema.sql statements. This is safe to call repeatedly.
func bootstrapSchema(opts *clickhouse.Options, retentionDays int) error {
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

	// Apply retention TTL idempotently (after tables exist).
	for _, stmt := range ttlStatements(retentionDays) {
		if err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("exec ttl statement: %w", err)
		}
	}

	return nil
}

// splitStatements splits a SQL script into individual statements on semicolons.
// Full-line "--" comments are stripped BEFORE splitting: a ';' inside a comment
// (e.g. "-- extend the enum; accept Negligible") must not split a statement, and
// a comment-only fragment would otherwise be sent to ClickHouse as an "Empty
// query" (code 62). Filters out empty or whitespace-only statements.
func splitStatements(sql string) []string {
	// Drop whole-line comments so their content — including any ';' — never
	// affects statement boundaries. Inline trailing comments are rare in the
	// bootstrap schema and are left as-is.
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	parts := strings.Split(b.String(), ";")
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
(ts, push_id, image_repo, image_tag, image_digest, identity, passed, failed_policies, reasons, base_image_id, scanner_db_version, duration_ms, image_created, image_age_days, image_age_threshold_days, image_age_known, infra_error, error_detail)
VALUES (now64(3), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.PushID, d.Repo, d.Tag, d.Digest, d.Identity, d.Passed,
		d.FailedPolicies, d.Reasons, d.BaseImageID, d.ScannerDBVersion, d.DurationMS,
		d.ImageCreated, d.ImageAgeDays, d.ImageAgeThresholdDays, d.ImageAgeKnown,
		d.InfraError, d.ErrorDetail)
}

// WriteTagAlias records a tag -> digest alias (see TagAliasWriter).
func (c *clickhouseWriter) WriteTagAlias(ctx context.Context, a TagAlias) error {
	return c.conn.Exec(ctx, `
INSERT INTO tag_aliases (ts, image_repo, image_tag, image_digest)
VALUES (now64(3), ?, ?, ?)`, a.Repo, a.Tag, a.Digest)
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

// FindingsByImageRef serves the scan-report endpoint by image reference instead of
// push_id, so a caller can use the repo:tag (or repo@sha256) they pushed. It
// resolves the MOST RECENT push for that repo whose tag or digest matches ref, then
// returns that push's findings. ref matches either image_tag (a tag, or the
// manifest digest when the client pushed by digest, e.g. buildx) or image_digest.
func (r *Reader) FindingsByImageRef(ctx context.Context, repo, ref string) ([]policy.Finding, error) {
	pushID, err := r.pushIDByRef(ctx, repo, ref)
	if err != nil {
		return nil, err
	}
	if pushID == "" {
		return nil, nil
	}
	return r.FindingsByPush(ctx, pushID)
}

// pushIDByRef resolves an image reference to the push_id of its most recent gate
// decision. Resolution order:
//  1. exact tag/digest match on gate_decisions;
//  2. tag_aliases (buildx: the tag was recorded on the forwarded index, the
//     decision on the image digest it references);
//  3. for a DIGEST ref only, the most recent push for the repo (the common "one
//     image in flight per repo" case; use repo@sha256:... to disambiguate).
//
// A TAG miss after (2) means that tag was never scanned; falling back would serve
// a different image's findings mislabeled as the requested tag, so it resolves to
// "" (no match). Query errors are returned, NOT masked as a miss — a ClickHouse
// outage must render "report unavailable", never "no findings".
func (r *Reader) pushIDByRef(ctx context.Context, repo, ref string) (string, error) {
	var pushID string
	row := r.conn.QueryRow(ctx,
		`SELECT toString(push_id) FROM gate_decisions
		 WHERE image_repo = ? AND (image_tag = ? OR image_digest = ?)
		 ORDER BY ts DESC LIMIT 1`, repo, ref, ref)
	err := row.Scan(&pushID)
	if err == nil {
		return pushID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	// Tag alias: resolve tag -> digest recorded when the index was forwarded.
	if !strings.HasPrefix(ref, "sha256:") {
		var digest string
		arow := r.conn.QueryRow(ctx,
			`SELECT image_digest FROM tag_aliases
			 WHERE image_repo = ? AND image_tag = ?
			 ORDER BY ts DESC LIMIT 1`, repo, ref)
		aerr := arow.Scan(&digest)
		if aerr == nil {
			drow := r.conn.QueryRow(ctx,
				`SELECT toString(push_id) FROM gate_decisions
				 WHERE image_repo = ? AND image_digest = ?
				 ORDER BY ts DESC LIMIT 1`, repo, digest)
			derr := drow.Scan(&pushID)
			if derr == nil {
				return pushID, nil
			}
			if !errors.Is(derr, sql.ErrNoRows) {
				return "", derr
			}
		} else if !errors.Is(aerr, sql.ErrNoRows) {
			return "", aerr
		}
	}

	if !refAllowsRepoFallback(ref) {
		return "", nil
	}
	row2 := r.conn.QueryRow(ctx,
		`SELECT toString(push_id) FROM gate_decisions
		 WHERE image_repo = ? ORDER BY ts DESC LIMIT 1`, repo)
	err2 := row2.Scan(&pushID)
	if err2 == nil {
		return pushID, nil
	}
	if !errors.Is(err2, sql.ErrNoRows) {
		return "", err2
	}
	return "", nil
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
