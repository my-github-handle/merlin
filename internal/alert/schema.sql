-- Suppression memory for the alert runner: one row per (detector, signature) with
-- the time it was last ANNOUNCED. This is the whole deduplication design — there is
-- no incident table and no lifecycle state.
--
-- It lives here rather than in internal/audit/schema.sql because it is the alerter's
-- own state, not audit data, and because it must NOT inherit the audit tables'
-- retention TTL: if these rows expired, every long-standing finding would be
-- re-announced the moment its row aged out.
--
-- ReplacingMergeTree keyed on (detector, signature) bounds the table to the number of
-- distinct finding classes, which is bounded in turn by Signature() normalization.
-- Reads still aggregate with max(notified_at) rather than trusting FINAL, because a
-- merge may not have happened yet.
CREATE TABLE IF NOT EXISTS alert_notifications (
    detector    String,
    signature   String,
    notified_at DateTime64(3),
    occurrences UInt64,
    summary     String
) ENGINE = ReplacingMergeTree(notified_at)
ORDER BY (detector, signature);
