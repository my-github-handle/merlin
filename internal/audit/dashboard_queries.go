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

func (r *Reader) TopCVEs(ctx context.Context, since time.Time, limit int) ([]CVECount, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.conn.Query(ctx, `
SELECT cve_id, any(severity), any(pkg_name), any(fixed_version), uniqExact(image_digest) AS imgs
FROM vulnerability_findings WHERE ts >= ?
GROUP BY cve_id ORDER BY imgs DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CVECount
	for rows.Next() {
		var c CVECount
		if err := rows.Scan(&c.CVE, &c.Severity, &c.Pkg, &c.FixedVersion, &c.ImageCount); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Reader) TopPackages(ctx context.Context, since time.Time, limit int) ([]LabeledCount, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.conn.Query(ctx, `
SELECT pkg_name, count() AS c FROM vulnerability_findings WHERE ts >= ?
GROUP BY pkg_name ORDER BY c DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabeledCount
	for rows.Next() {
		var lc LabeledCount
		if err := rows.Scan(&lc.Label, &lc.Count); err != nil {
			return nil, err
		}
		out = append(out, lc)
	}
	return out, rows.Err()
}

func (r *Reader) SeverityTotalsSince(ctx context.Context, since time.Time) (SeverityTotals, error) {
	var s SeverityTotals
	row := r.conn.QueryRow(ctx, `
SELECT
  countIf(severity='CRITICAL'), countIf(severity='HIGH'),
  countIf(severity='MEDIUM'), countIf(severity='LOW'), countIf(severity='UNKNOWN')
FROM vulnerability_findings WHERE ts >= ?`, since)
	if err := row.Scan(&s.Critical, &s.High, &s.Medium, &s.Low, &s.Unknown); err != nil {
		return SeverityTotals{}, err
	}
	return s, nil
}

func (r *Reader) FixAvailabilitySince(ctx context.Context, since time.Time, limit int) (FixAvailability, error) {
	if limit <= 0 {
		limit = 10
	}
	var fa FixAvailability
	rows, err := r.conn.Query(ctx, `
SELECT severity, count() AS total, countIf(fixed_version != '') AS fixable
FROM vulnerability_findings WHERE ts >= ?
GROUP BY severity ORDER BY total DESC`, since)
	if err != nil {
		return FixAvailability{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var fr FixAvailabilityRow
		if err := rows.Scan(&fr.Severity, &fr.Total, &fr.Fixable); err != nil {
			return FixAvailability{}, err
		}
		fa.BySeverity = append(fa.BySeverity, fr)
	}
	if err := rows.Err(); err != nil {
		return FixAvailability{}, err
	}
	// Top fixable CVEs by image impact.
	frows, err := r.conn.Query(ctx, `
SELECT cve_id, any(severity), any(pkg_name), any(fixed_version), uniqExact(image_digest) AS imgs
FROM vulnerability_findings WHERE ts >= ? AND fixed_version != ''
GROUP BY cve_id ORDER BY imgs DESC LIMIT ?`, since, limit)
	if err != nil {
		return FixAvailability{}, err
	}
	defer frows.Close()
	for frows.Next() {
		var c CVECount
		if err := frows.Scan(&c.CVE, &c.Severity, &c.Pkg, &c.FixedVersion, &c.ImageCount); err != nil {
			return FixAvailability{}, err
		}
		fa.TopFixable = append(fa.TopFixable, c)
	}
	return fa, frows.Err()
}

func (r *Reader) BaseImagePosture(ctx context.Context, since time.Time) ([]BaseImageStat, error) {
	rows, err := r.conn.Query(ctx, `
SELECT base_image_id, count() AS total, countIf(passed) AS passed
FROM gate_decisions WHERE ts >= ?
GROUP BY base_image_id ORDER BY total DESC LIMIT 50`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BaseImageStat
	for rows.Next() {
		var b BaseImageStat
		if err := rows.Scan(&b.BaseImageID, &b.Total, &b.Passed); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (r *Reader) ByIdentity(ctx context.Context, since time.Time, limit int) ([]IdentityStat, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.conn.Query(ctx, `
SELECT identity, count() AS total, countIf(passed) AS passed
FROM gate_decisions WHERE ts >= ?
GROUP BY identity ORDER BY total DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IdentityStat
	for rows.Next() {
		var s IdentityStat
		if err := rows.Scan(&s.Identity, &s.Total, &s.Passed); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Reader) ByRepo(ctx context.Context, since time.Time, limit int) ([]RepoStat, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.conn.Query(ctx, `
SELECT image_repo, count() AS total, countIf(passed) AS passed
FROM gate_decisions WHERE ts >= ?
GROUP BY image_repo ORDER BY total DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RepoStat
	for rows.Next() {
		var s RepoStat
		if err := rows.Scan(&s.Repo, &s.Total, &s.Passed); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
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
