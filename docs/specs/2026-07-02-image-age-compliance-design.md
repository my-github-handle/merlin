# Image Age Compliance — Design

**Date:** 2026-07-02
**Status:** SUPERSEDED by [`2026-07-03-merlin-image-age-compliance-spec.md`](./2026-07-03-merlin-image-age-compliance-spec.md)
**Related:** `github.com/c3-e/c3aiops/cmd/imageComplianceReport` (reference tool)

> **Superseded.** This draft proposed image age as *reported metadata only*
> ("report now, policy later"). The authoritative c3aiops service spec dated
> 2026-07-03 instead requires image age to be a **blocking gate policy** (default
> 60 days → 400, configurable/disable-able per tenant, fail-closed when `created`
> is unreadable). Implement the 2026-07-03 spec; this document is retained only
> for its verified data-path notes (OCI config `created` source, staging/audit/
> dashboard wiring), which remain accurate.

## Problem

Merlin gates image pushes on CVE scan (Trivy) and base-image policy, but has no
notion of how *old* an image is. A stale image — even one with no CRITICAL CVE
today — is a compliance risk: it drifts from the current patched base and
accumulates undisclosed vulnerabilities. The C3 `imageComplianceReport` tool
already enforces a **60-day age threshold** across the release manifest, but it
does so out-of-band (a batch CI job that `docker pull`s each image and runs
`docker inspect {{.Created}}`).

Merlin is the natural place to compute and surface image age: it already
assembles every pushed image and holds the OCI config blob in staging, so it can
read the `created` timestamp **in-band, server-side, with zero extra pulls**.

## Goal

Compute each pushed image's age from its OCI config `created` timestamp and
**return it** everywhere Merlin already surfaces gate outcomes: the push response
header, the `GET /reports/<ref>` payload, the ClickHouse audit record, and the
dashboard.

**Explicit non-goal (this phase):** blocking a push on age. Age is reported
metadata only; it never changes a push's pass/fail. The design is structured so a
blocking threshold can be switched on later (see "Future: blocking policy")
without reworking the data path.

## Approach: report now, policy later

Chosen over two alternatives:

- **Blocking policy now** — add age as a gate policy that rejects images over a
  threshold. Rejected: higher risk (a new 400 reject path that could block
  legitimate pushes on day one), and the literal ask is to *return* age. Deferred
  to a later phase once age data is trusted in production.
- **Report-only, no forward-looking config** — simplest, but would need rework to
  add blocking later. Rejected in favor of threading a nullable threshold through
  config now so the policy switch is a small follow-up.

"Report now, policy later" ships the low-risk, literal feature and lays the
groundwork for enforcement.

## Where age comes from

The OCI image **config blob** (JSON, `application/vnd.oci.image.config.v1+json`
or the Docker equivalent) has a top-level `created` field in RFC3339. During a
push Merlin stages this blob; its digest is `ManifestRef.ConfigDigest`, and the
bytes are fetchable via `staging.Store.GetStagedBlob(ctx, configDigest)`. The
project already depends on `github.com/google/go-containerregistry` (v0.21.7),
whose `v1.ConfigFile.Created` parses this field.

**Source of truth:** the OCI config `created` timestamp. This matches the
reference tool's primary method (`docker inspect {{.Created}}` reads the same
field). We do **not** replicate the reference tool's Chainguard tag-timestamp
regex fallback — Merlin has the real config in hand, so it never needs to infer
age from a tag. If `created` is absent or unparseable (some reproducible builds
zero it to the Unix epoch), age is reported as **unknown** (see error handling).

## Components and data flow

The age value threads through the existing gate pipeline. No new subsystem; each
touched unit keeps its current responsibility.

1. **`policy.StagedImage`** — gains `Created time.Time` (zero value = unknown).
   Populated once, during assembly, from the config blob.

2. **`staging.Store.Assemble`** (or its caller in `manifest.go`) — reads the
   config blob it already has, parses `created`, and sets `StagedImage.Created`.
   This is the single point where the timestamp is extracted. Parsing lives in a
   small, testable helper: `imageage.CreatedFromConfig([]byte) (time.Time, error)`.

3. **`policy.Result`** — gains `ImageCreated time.Time` and a derived
   `ImageAgeDays int` (age at evaluation time). The engine copies these through
   from the `StagedImage` when aggregating verdicts. Age is a property of the
   image, not of any one policy, so it lives on `Result` directly rather than in a
   `Verdict`.

4. **`router.SummarizeResult`** — appends age to the one-line summary, e.g.
   `scan clean: 0 CRITICAL, 3 HIGH — image age 45d`. On reject the age is likewise
   appended so a rejected push still reports it.

5. **Response header** — `manifest.go` sets `X-Merlin-Image-Age-Days` on the
   manifest PUT response (alongside the existing `X-Merlin-Scan-Report-URL`), so
   a CI client can read age without a second call. Set on both pass and reject.

6. **Audit (`audit.Decision` + ClickHouse)** — `Decision` gains
   `ImageCreated time.Time` and `ImageAgeDays uint16`. The `gate_decisions` table
   gains two columns: `image_created DateTime64(3)` and `image_age_days UInt16`.
   The insert column list and `Reader` decision queries are updated to match.

7. **Dashboard** — the per-image report view (`ReportVM`) and the images table row
   (`ImageVM`) gain the age (days + created date), rendered next to the verdict.
   Read from the new audit columns.

```
push → assemble → read config.created ──┐
                                        ├─→ StagedImage.Created
gate (engine) ──────────────────────────┘         │
   │                                               ▼
   └─→ Result{ImageCreated, ImageAgeDays} ─┬─→ SummarizeResult → response body
                                           ├─→ X-Merlin-Image-Age-Days header
                                           ├─→ audit.Decision → ClickHouse
                                           └─→ dashboard (report + images table)
```

## Age computation

`ImageAgeDays = floor(time.Since(created).Hours() / 24)`, matching the reference
tool's `CalculateAgeInDays`. Computed once at evaluation time and stored, so the
reported age is stable for a given push (not recomputed on each report read — a
report for an old push shows the age *as of the push*, which is the auditable
fact). The dashboard may additionally show "current age" derived from the stored
`image_created` if a live value is wanted; that is a presentation choice, not
stored data.

## Error handling

- **Config blob missing / unfetchable:** assembly already fails the push for a
  missing config; no new path. If the config is present but has no `created`
  field or an unparseable one, `CreatedFromConfig` returns an error; the caller
  logs it and leaves `StagedImage.Created` as the zero value.
- **Unknown age representation:** zero `time.Time` ⇒ age is *unknown*, not zero
  days. Resolved representation: the summary omits the age suffix; the
  `X-Merlin-Image-Age-Days` header is **omitted entirely** (absent header = age
  unknown, cleaner for clients than a `-1` magic value); the audit
  `image_created` is stored as `0` (epoch) which the readers already map to
  "unknown"; `image_age_days` is stored as `0` but is only meaningful when
  `image_created != 0` (readers key "unknown" off `image_created == 0`, never off
  the age integer). The dashboard renders "unknown". **Unknown age never fails a
  push** in this phase — parsing is best-effort and non-fatal.
- **Clock skew / future `created`:** if `created` is in the future (negative
  age), age is clamped to 0 and reported as such.

## Testing

- **Unit — `imageage.CreatedFromConfig`:** valid RFC3339 config → correct time;
  missing field → error; malformed JSON → error; epoch-zero created → treated per
  the unknown rule. Table-driven.
- **Unit — age arithmetic:** created N days ago → N; future created → 0; unknown
  → unknown sentinel. Uses an injected `now` for determinism (no wall clock in
  tests).
- **Unit — `SummarizeResult`:** age suffix present on pass and reject; omitted
  when unknown.
- **Integration — manifest PUT:** a staged image with a known `created` surfaces
  the `X-Merlin-Image-Age-Days` header and the age in the report; extends the
  existing `http_push_integration_test.go` fixtures.
- **Integration — audit round-trip:** a recorded decision reads back with the
  correct `image_created` / `image_age_days` (extends the ClickHouse integration
  test).
- Race detector on the touched packages (`go test -race`).

## Schema migration

`gate_decisions` gains two nullable-by-default columns. ClickHouse `ADD COLUMN`
is online and backfills existing rows with the column default, so the migration
is non-breaking:

```sql
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_created DateTime64(3) DEFAULT 0;
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_age_days UInt16 DEFAULT 0;
```

`schema.sql` is updated for fresh installs; the `ALTER`s cover existing
deployments. Old rows read back with `image_created = 0` ⇒ rendered "unknown".

## Future: blocking policy (out of scope, designed-for)

A later phase can add an `AgePolicy` implementing `policy.Policy` that fails the
verdict when `ImageAgeDays > threshold`. Config gains
`policy.max_image_age_days` (nullable; unset = report-only, matching this
phase's behavior). No data-path change is required — age is already computed and
threaded — so enabling enforcement is: (1) read the config value, (2) register
the policy, (3) return a failing `Verdict` with a reason. The reference tool's
60-day default is the natural starting threshold.

## Documentation

`docs/USAGE.md` and `docs/CI.md` gain a short "Image age" note: where age comes
from, the `X-Merlin-Image-Age-Days` header, and that it is currently reported,
not enforced.
