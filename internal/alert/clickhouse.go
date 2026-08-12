package alert

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

//go:embed schema.sql
var schemaSQL string

// Store reads the audit window and remembers what has already been announced. It
// satisfies both Source and Cooldowns from one connection: the alerter makes four
// small queries every fifteen minutes, so a second pool would be cost without
// benefit.
type Store struct {
	conn driver.Conn
}

// The Store is the only production implementation of both interfaces, and the
// runner takes them separately, so nothing else would catch a drifted signature.
var (
	_ Source    = (*Store)(nil)
	_ Cooldowns = (*Store)(nil)
)

// NewClickHouseStore connects and creates the notifications table if it is missing.
//
// It does NOT create the database or the gate_decisions table: audit's writer owns
// that bootstrap and runs first (see internal/app). If gate_decisions is missing here
// the queries fail, which is the correct outcome — an alerter that silently reports
// "no findings" against a missing table is worse than one that logs an error.
func NewClickHouseStore(dsn string) (*Store, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse clickhouse dsn: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	if err := conn.Ping(context.Background()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}
	if err := conn.Exec(context.Background(), schemaSQL); err != nil {
		conn.Close()
		return nil, fmt.Errorf("create alert_notifications: %w", err)
	}
	return &Store{conn: conn}, nil
}

func (s *Store) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// InfraErrorDetails groups the window's infra-error decisions by error_detail.
//
// WHERE infra_error is the load-bearing clause: a decision that failed POLICY is a
// working gate saying no, and alerting on those would bury every real finding under
// the normal rejection traffic.
func (s *Store) InfraErrorDetails(ctx context.Context, since, until time.Time, limit int) ([]DetailCount, error) {
	if limit <= 0 {
		limit = DefaultDetailLimit
	}
	rows, err := s.conn.Query(ctx, `
SELECT error_detail, count() AS c, min(ts) AS first_seen, max(ts) AS last_seen
FROM gate_decisions
WHERE ts >= ? AND ts < ? AND infra_error AND error_detail != ''
GROUP BY error_detail
ORDER BY c DESC
LIMIT ?`, since, until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DetailCount
	for rows.Next() {
		var d DetailCount
		if err := rows.Scan(&d.Detail, &d.Count, &d.First, &d.Last); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DecisionCounts returns the window's decision total and infra-error count.
func (s *Store) DecisionCounts(ctx context.Context, since, until time.Time) (Counts, error) {
	var c Counts
	// The alias MUST NOT be "infra_error". On strict ClickHouse versions an alias that
	// shadows the aggregated column parses as an aggregate inside an aggregate
	// (ILLEGAL_AGGREGATION, code 184) and the whole query fails — the same trap
	// documented on DecisionStatsSince in internal/audit/dashboard_queries.go.
	row := s.conn.QueryRow(ctx, `
SELECT count() AS total, countIf(infra_error) AS n_infra
FROM gate_decisions WHERE ts >= ? AND ts < ?`, since, until)
	if err := row.Scan(&c.Total, &c.InfraErrors); err != nil {
		return Counts{}, err
	}
	return c, nil
}

// LastNotified returns the last announcement time per cooldown key.
func (s *Store) LastNotified(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.conn.Query(ctx, `
SELECT detector, signature, max(notified_at) AS last_at
FROM alert_notifications GROUP BY detector, signature`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var detector, signature string
		var at time.Time
		if err := rows.Scan(&detector, &signature, &at); err != nil {
			return nil, err
		}
		out[detector+"|"+signature] = at
	}
	return out, rows.Err()
}

// RecordNotified stamps a finding class as announced. Append-only: the table's
// ReplacingMergeTree collapses duplicates in the background and LastNotified
// aggregates, so no update path is needed.
func (s *Store) RecordNotified(ctx context.Context, f Finding, at time.Time) error {
	return s.conn.Exec(ctx, `
INSERT INTO alert_notifications (detector, signature, notified_at, occurrences, summary)
VALUES (?, ?, ?, ?, ?)`, f.Detector, f.Signature, at, f.Count, f.Summary)
}
