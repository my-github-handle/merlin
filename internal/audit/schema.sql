CREATE TABLE IF NOT EXISTS gate_decisions (
    ts               DateTime64(3),
    push_id          UUID,
    image_repo       String,
    image_tag        String,
    image_digest     String,
    identity         String,
    passed           Bool,
    failed_policies  Array(String),
    reasons          Array(String),
    base_image_id    String,
    trivy_db_version String,
    duration_ms      UInt32
) ENGINE = MergeTree
ORDER BY (image_digest, ts);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
    ts             DateTime64(3),
    push_id        UUID,
    image_digest   String,
    image_repo     String,
    cve_id         String,
    severity       Enum8('LOW'=1,'MEDIUM'=2,'HIGH'=3,'CRITICAL'=4,'UNKNOWN'=0),
    pkg_name       String,
    pkg_version    String,
    fixed_version  String,
    base_image_id  String,
    identity       String
) ENGINE = MergeTree
ORDER BY (cve_id, severity, ts);

-- Projections / skip indexes for non-primary-key reverse lookups.
ALTER TABLE vulnerability_findings ADD INDEX IF NOT EXISTS idx_pkg (pkg_name) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE vulnerability_findings ADD INDEX IF NOT EXISTS idx_identity (identity) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE gate_decisions ADD INDEX IF NOT EXISTS idx_identity (identity) TYPE bloom_filter GRANULARITY 4;
