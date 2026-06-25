package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/merlin-gate/merlin/internal/policy"
)

type clickhouseWriter struct {
	conn driver.Conn
}

// NewClickHouseWriter connects to ClickHouse via a DSN.
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
	return &clickhouseWriter{conn: conn}, nil
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

func nowFn() time.Time { return time.Now() }
