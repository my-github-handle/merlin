package audit

import (
	"context"
	"time"
)

func (r *Reader) RecentDecisions(ctx context.Context, limit int) ([]DecisionSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.conn.Query(ctx, `
SELECT ts, toString(push_id), image_repo, image_tag, image_digest, identity, passed, reasons
FROM gate_decisions ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DecisionSummary
	for rows.Next() {
		var d DecisionSummary
		if err := rows.Scan(&d.Ts, &d.PushID, &d.Repo, &d.Tag, &d.Digest, &d.Identity, &d.Passed, &d.Reasons); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *Reader) DecisionStatsSince(ctx context.Context, since time.Time) (DecisionStats, error) {
	var s DecisionStats
	row := r.conn.QueryRow(ctx, `
SELECT
  count() AS total,
  countIf(passed) AS passed,
  countIf(NOT passed) AS rejected,
  quantile(0.5)(duration_ms) AS p50,
  quantile(0.95)(duration_ms) AS p95,
  quantile(0.99)(duration_ms) AS p99
FROM gate_decisions WHERE ts >= ?`, since)
	if err := row.Scan(&s.Total, &s.Passed, &s.Rejected, &s.Latency.P50, &s.Latency.P95, &s.Latency.P99); err != nil {
		return DecisionStats{}, err
	}
	// Top reject reasons (reasons is Array(String); arrayJoin explodes it).
	rrows, err := r.conn.Query(ctx, `
SELECT reason, count() AS c FROM (
  SELECT arrayJoin(reasons) AS reason FROM gate_decisions WHERE ts >= ? AND NOT passed
) GROUP BY reason ORDER BY c DESC LIMIT 10`, since)
	if err != nil {
		return DecisionStats{}, err
	}
	defer rrows.Close()
	for rrows.Next() {
		var lc LabeledCount
		if err := rrows.Scan(&lc.Label, &lc.Count); err != nil {
			return DecisionStats{}, err
		}
		s.RejectReasons = append(s.RejectReasons, lc)
	}
	return s, rrows.Err()
}

func (r *Reader) DecisionHeaderByPush(ctx context.Context, pushID string) (DecisionHeader, error) {
	return r.scanHeader(ctx, `
SELECT toString(push_id), image_repo, image_tag, image_digest, identity, passed,
       failed_policies, reasons, base_image_id, trivy_db_version, ts
FROM gate_decisions WHERE push_id = ? ORDER BY ts DESC LIMIT 1`, pushID)
}

func (r *Reader) DecisionHeaderByRef(ctx context.Context, repo, ref string) (DecisionHeader, error) {
	h, err := r.scanHeader(ctx, `
SELECT toString(push_id), image_repo, image_tag, image_digest, identity, passed,
       failed_policies, reasons, base_image_id, trivy_db_version, ts
FROM gate_decisions WHERE image_repo = ? AND (image_tag = ? OR image_digest = ?)
ORDER BY ts DESC LIMIT 1`, repo, ref, ref)
	if err != nil {
		return DecisionHeader{}, err
	}
	if h.Found {
		return h, nil
	}
	// Fall back to the most recent push for the repo (mirrors FindingsByImageRef).
	return r.scanHeader(ctx, `
SELECT toString(push_id), image_repo, image_tag, image_digest, identity, passed,
       failed_policies, reasons, base_image_id, trivy_db_version, ts
FROM gate_decisions WHERE image_repo = ? ORDER BY ts DESC LIMIT 1`, repo)
}

// scanHeader runs a single-row header query; Found is false when no row matched.
func (r *Reader) scanHeader(ctx context.Context, q string, args ...any) (DecisionHeader, error) {
	var h DecisionHeader
	row := r.conn.QueryRow(ctx, q, args...)
	err := row.Scan(&h.PushID, &h.Repo, &h.Tag, &h.Digest, &h.Identity, &h.Passed,
		&h.FailedPolicies, &h.Reasons, &h.BaseImageID, &h.TrivyDBVersion, &h.Ts)
	if err != nil {
		// clickhouse-go returns sql.ErrNoRows-equivalent on no row; treat any scan
		// error on a single-row lookup as "not found" rather than a hard failure,
		// so a missing report renders an empty state, not a 500.
		return DecisionHeader{Found: false}, nil
	}
	h.Found = true
	return h, nil
}

// ImagesPage returns one page of gated images (newest first) with severity tallies,
// plus the total matching count. All caller input is bound as parameters.
func (r *Reader) ImagesPage(ctx context.Context, since time.Time, f ImageFilter, limit, offset int) (ImagePage, error) {
	if limit <= 0 {
		limit = 10
	}
	if offset < 0 {
		offset = 0
	}
	// Build the WHERE clause from bound predicates.
	where := "ts >= ?"
	args := []any{since}
	if f.Text != "" {
		where += " AND (positionCaseInsensitive(image_repo, ?) > 0 OR positionCaseInsensitive(image_tag, ?) > 0 OR positionCaseInsensitive(identity, ?) > 0)"
		args = append(args, f.Text, f.Text, f.Text)
	}
	if f.RejectedOnly {
		where += " AND passed = false"
	}

	var page ImagePage
	// Total count (pre-pagination). hasCritical needs the findings join, so count from the same CTE.
	// Use a subquery that resolves per-push severity tallies, then filter/count.
	base := `
WITH per_push AS (
  SELECT d.ts AS ts, d.push_id AS push_id, d.image_repo AS image_repo, d.image_tag AS image_tag,
         d.image_digest AS image_digest, d.identity AS identity, d.passed AS passed,
         countIf(f.severity = 'CRITICAL') AS crit, countIf(f.severity = 'HIGH') AS high,
         countIf(f.severity = 'MEDIUM') AS med, countIf(f.severity = 'LOW') AS low
  FROM gate_decisions d
  LEFT JOIN vulnerability_findings f ON f.push_id = d.push_id
  WHERE ` + where + `
  GROUP BY ts, push_id, image_repo, image_tag, image_digest, identity, passed
)`
	having := ""
	if f.HasCritical {
		having = " WHERE crit > 0"
	}

	// Total.
	if err := r.conn.QueryRow(ctx, base+" SELECT count() FROM per_push"+having, args...).Scan(&page.Total); err != nil {
		return ImagePage{}, err
	}
	// Page rows.
	rowArgs := append(append([]any{}, args...), limit, offset)
	rows, err := r.conn.Query(ctx, base+
		" SELECT ts, toString(push_id), image_repo, image_tag, image_digest, identity, passed, crit, high, med, low FROM per_push"+
		having+" ORDER BY ts DESC LIMIT ? OFFSET ?", rowArgs...)
	if err != nil {
		return ImagePage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var ir ImageRow
		if err := rows.Scan(&ir.Ts, &ir.PushID, &ir.Repo, &ir.Tag, &ir.Digest, &ir.Identity, &ir.Passed,
			&ir.Crit, &ir.High, &ir.Med, &ir.Low); err != nil {
			return ImagePage{}, err
		}
		page.Rows = append(page.Rows, ir)
	}
	return page, rows.Err()
}
