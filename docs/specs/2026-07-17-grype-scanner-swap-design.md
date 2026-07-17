# Design: Replace Trivy with Grype

**Date:** 2026-07-17
**Status:** Approved (pending spec review)
**Type:** Scanner replacement (hard swap, breaking rename)

## Goal

Replace Trivy with [Grype](https://github.com/anchore/grype) as Merlin's
vulnerability scanner. This is a **hard replacement** — Trivy is removed
entirely, not kept behind a pluggable interface. The scan policy, binary,
config keys, audit-schema column, and internal field names are renamed to be
scanner-appropriate (Grype-specific or scanner-agnostic where that reads better).

## Non-Goals

- No pluggable multi-scanner abstraction (explicitly rejected — YAGNI).
- No change to DB-delivery model (Grype downloads its DB at runtime over the
  pod's existing egress, exactly as Trivy does today).
- No change to the gate/push flow, staging, or ACR push.

## Current State (as explored)

Trivy is cleanly isolated:

- `internal/policies/trivy/` — 3 files (~155 LOC + tests):
  - `exec_runner.go`: `Runner` interface + exec of `trivy image --input <ociPath> --format json --quiet`.
  - `report.go`: `ParseReport` for Trivy JSON (`Results[].Vulnerabilities[]`), yields `policy.Finding`.
  - `trivy.go`: `Policy` (implements `policy.Policy`): `Name() "trivy"`, `Evaluate`, severity ranking `LOW<MEDIUM<HIGH<CRITICAL` (+ UNKNOWN).
- `internal/app/app.go`: `trivy.New(trivy.NewExecRunner("trivy"), cfg.Trivy.SeverityThreshold)`.
- `internal/config/config.go`: `Trivy` config struct + `severity_threshold` key.
- `Dockerfile`: `FROM aquasec/trivy:0.71.2 AS trivy`; `COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy`; runtime-DB comment block.
- DB-version threading: the Verdict already carries `ScannerDBVersion`
  (scanner-agnostic), and `engine.go:39` maps `v.ScannerDBVersion` →
  `res.TrivyDBVersion`. The `Trivy`-named field persists only on the
  **Result → audit → dashboard** path:
  - `policy.Result.TrivyDBVersion` (policy.go:67)
  - `audit.Decision.TrivyDBVersion` (audit.go:23), written to ClickHouse column
    `trivy_db_version` on **`gate_decisions` only** (schema.sql:12; NOT on
    `vulnerability_findings`).
  - `audit.DecisionHeader.TrivyDBVersion` (dashboard_reader.go:54),
    read in `dashboard_queries.go`.
  - `dashboard.ReportVM.TrivyDBVersion` (view.go:56), set in data.go:87,
    rendered in `report.html:7` ("trivy {{.VM.TrivyDBVersion}}").

## Design

### 1. Package & interface (`internal/policies/grype/`)

Rename the package `trivy` → `grype`, keeping the same shape:

- **`Runner`** — unchanged signature `Scan(ctx, ociPath) (Report, error)`.
  `exec_runner.go` command becomes `grype <ociPath> -o json -q`. Grype
  auto-detects the OCI layout directory; if detection is unreliable we prefix
  the input as `oci-dir:<ociPath>`. Determined against a real fixture during
  implementation.
- **`ParseReport`** — new parser for Grype native JSON:
  - iterate `matches[]`
  - `vulnerability.id` → `Finding.CVE`
  - `vulnerability.severity` → `Finding.Severity`
  - `artifact.name` / `artifact.version` → `Finding.Pkg` / `Finding.Version`
  - `vulnerability.fix.versions[0]` (if present) → `Finding.FixedVersion`
  - DB identity from `descriptor.db.schemaVersion` + `descriptor.db.built`
    combined into one `Report.DBVersion` string.
  - Validate the payload is a real Grype report (e.g. presence of `descriptor`
    or `matches` key) rather than trusting empty JSON, mirroring Trivy's
    SchemaVersion guard.
- **`Policy`** — same `policy.Policy` interface. `Name()` returns `"grype"`.
  Severity ranking extended to Grype's set:
  `Negligible < Low < Medium < High < Critical`, plus `Unknown`. Threshold
  semantics unchanged (fail on findings at/above the configured severity;
  unrecognized severities are surfaced as a reason, as Trivy does today).

### 2. Config, wiring, Dockerfile

- **Config**: rename `Trivy` struct → `Grype`; key `trivy.severity_threshold`
  → `grype.severity_threshold`. Update helm `charts/merlin/templates/configmap.yaml`
  and `values.yaml`, and any deployed YAML, so the live config keeps parsing.
- **Wiring** (`app.go`): `grype.New(grype.NewExecRunner("grype"), cfg.Grype.SeverityThreshold)`.
- **Dockerfile**: replace the trivy stage with `FROM anchore/grype:<pinned-tag> AS grype`
  and `COPY --from=grype /grype /usr/local/bin/grype`. Remove the trivy binary
  copy. Update the runtime-DB comment: Grype downloads its DB over egress;
  cache dir `GRYPE_DB_CACHE_DIR` (default `~/.cache/grype/db`). Pin an explicit
  grype version tag (not `latest`).

### 3. Schema migration & field threading

- **ClickHouse**: `ALTER TABLE merlin.gate_decisions RENAME COLUMN
  trivy_db_version TO scanner_db_version` (metadata-only, instant).
  `vulnerability_findings` is unaffected (no such column). Update
  `internal/audit/schema.sql` so fresh installs match.
- **Go field rename** (scanner-agnostic `ScannerDBVersion` / `scanner_db_version`):
  - `policy.Result.TrivyDBVersion` → `ScannerDBVersion` (policy.go). This also
    lets `engine.go:39` become the identity `res.ScannerDBVersion = v.ScannerDBVersion`.
  - `audit.Decision.TrivyDBVersion` → `ScannerDBVersion`; INSERT column name in
    clickhouse.go → `scanner_db_version`.
  - `audit.DecisionHeader.TrivyDBVersion` → `ScannerDBVersion`; SELECT in
    dashboard_queries.go.
  - `dashboard.ReportVM.TrivyDBVersion` → `ScannerDBVersion` (view.go, data.go).
  - `outcome.go:129` assignment.
- **Report/dashboard UI**: `report.html` label "trivy {{.VM.TrivyDBVersion}}"
  → "scanner {{.VM.ScannerDBVersion}}". If the `/report` JSON exposes a
  `trivy_db_version` key, rename to `scanner_db_version`.
- **Metrics** (`observability/metrics.go`): rename any `trivy`-named metric or
  label to `scanner`/`grype`.

**Migration ordering (expand/contract) to avoid a schema/binary mismatch window:**
1. `ALTER TABLE ... ADD COLUMN scanner_db_version String` (keep `trivy_db_version`).
2. Deploy the new binary: writes `scanner_db_version`; reads prefer
   `scanner_db_version`, tolerating the old column during transition.
3. Once the new binary is live and healthy, `ALTER TABLE ... DROP COLUMN trivy_db_version`.

Rationale: a bare `RENAME COLUMN` would break the currently-running binary's
queries the instant it runs. Expand/contract keeps old and new binaries valid
against the intermediate schema. (If a brief coordinated cutover is acceptable,
a single `RENAME` + simultaneous deploy is simpler — implementation plan will
pick based on tolerance for a few seconds of query errors. Default: expand/contract.)

### 4. Testing

- **TDD**: write the Grype-fixture parser test first (RED), implement `ParseReport`,
  then port the Policy and exec-runner tests.
- **Fixtures**: capture real `grype <known-vulnerable-image> -o json` output as
  the parser fixture — including a `Negligible` finding and a multi-`fix.versions`
  entry — so the parser is tested against actual schema, not a guess.
- Port `report_test.go`, `trivy_test.go` → `grype_test.go`, `exec_runner_test.go`.
- Update the ~20 test files referencing `trivy` / `TrivyDBVersion` across app,
  ingress/docker, dashboard, audit (mechanical; `go build ./...` catches misses).
- Gate: `go build ./...`, `go test -race ./...`, `go vet -tags integration ./...`,
  and a live smoke push through the gate before/after the deploy.

## Risks

- **Grype JSON schema drift** — mitigated by pinning the grype image version and
  testing against a real captured fixture.
- **Severity semantics differ** — Grype adds `Negligible`; ranking updated. A
  threshold of e.g. "HIGH" behaves the same (Critical/High fail).
- **DB-download egress at first scan** — identical operational profile to Trivy
  today; no new risk.
- **Schema/binary mismatch** — avoided via expand/contract migration.

## Out of scope / follow-ups

- Durable cap on ClickHouse `system.*_log` tables (separate incident follow-up).
- Any change to which severities gate (threshold value stays as configured).
