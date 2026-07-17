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
    scanner_db_version String,
    duration_ms      UInt32,
    image_created            DateTime64(3) DEFAULT 0,
    image_age_days           UInt16 DEFAULT 0,
    image_age_threshold_days UInt16 DEFAULT 0,
    image_age_known          Bool DEFAULT 0
) ENGINE = MergeTree
ORDER BY (image_digest, ts);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
    ts             DateTime64(3),
    push_id        UUID,
    image_digest   String,
    image_repo     String,
    cve_id         String,
    severity       Enum8('UNKNOWN'=0,'LOW'=1,'MEDIUM'=2,'HIGH'=3,'CRITICAL'=4,'NEGLIGIBLE'=5),
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

-- Online ALTER for existing deployments: add age columns.
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_created DateTime64(3) DEFAULT 0;
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_age_days UInt16 DEFAULT 0;
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_age_threshold_days UInt16 DEFAULT 0;
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_age_known Bool DEFAULT 0;
-- Online ALTER for existing deployments: scanner-agnostic DB-version column.
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS scanner_db_version String;
-- Grype emits Negligible; extend the findings severity enum to accept it.
ALTER TABLE vulnerability_findings MODIFY COLUMN severity Enum8('UNKNOWN'=0,'LOW'=1,'MEDIUM'=2,'HIGH'=3,'CRITICAL'=4,'NEGLIGIBLE'=5);
