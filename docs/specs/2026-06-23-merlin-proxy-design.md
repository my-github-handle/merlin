# Merlin — Image Publishing Gate Proxy: Design Spec

**Date:** 2026-06-23
**Status:** Approved (design)

## 1. Purpose

Merlin is a transparent Docker Registry V2 proxy that gates every image push to a
backend ACR (Azure Container Registry) dev repository. A push only reaches ACR
after the image passes a policy gate: a Trivy vulnerability scan and a base-image
policy. Because Merlin's own service identity is the **only** identity with write
access to ACR, there is no path to publish an unscanned image.

**v1 gate checks:**
- **Trivy vulnerability scan** — fail on any `CRITICAL` severity finding.
- **Base-image policy** — image must be built on RedHat UBI or Chainguard/Wolfi.

The policy engine is extensible: future checks (signing, SBOM, non-root, etc.) are
added as new policies without changing the gate.

## 2. Interaction Model

Developers use standard Docker tooling — no workflow change:

```
docker login merlin.internal           # Entra ID identity
docker push merlin.internal/<repo>:<tag>
```

The push blocks until the gate completes. On pass, `docker push` succeeds and the
image is in ACR. On fail, `docker push` fails with a message explaining which
policy rejected it and why.

## 3. Architecture

Single Go binary implementing the inbound side of the Docker Registry V2 HTTP API.

```
                         ┌─────────────────── Merlin proxy (Go) ──────────────────────┐
 docker push             │                                                              │
 (Entra ID auth) ───────►│  v2 API handler ──► staging store (local OCI layout)         │
                         │       │                      │                               │
                         │       │  (manifest = done)   ▼                               │
                         │       └────────────►  policy gate ──► [Trivy] [base-image]    │
                         │                              │  pass         policy           │
                         │                              ▼                                 │
                         │                       ACR pusher ──(Managed Identity)──────────┼──► ACR dev repo
                         │                              │  fail                            │
                         │                              ▼                                 │
                         │                       reject + cleanup                         │
                         │                                                              │
                         │  observability (OTel: /metrics, logs, traces) ───────────────┼──► Prometheus / Azure Monitor
                         │  audit (every decision + findings, async/batched) ───────────┼──► ClickHouse
                         └──────────────────────────────────────────────────────────────┘
```

Every gate decision is emitted to observability (metrics/traces/logs) and to the
`audit` store (ClickHouse) regardless of pass/fail.

### Components (each its own package, independently testable)

| Package | Responsibility | Depends on |
|---|---|---|
| `registryv2` | Inbound V2 protocol handler (blob upload, manifest PUT, required GETs) | `auth`, `staging`, `policy`, `acr` |
| `auth` | Entra ID bearer-token validation on inbound requests | Entra JWKS |
| `staging` | Local OCI-layout store for buffered blobs/manifests; assembles complete image | filesystem |
| `policy` | Extensible gate engine; runs registered policies, aggregates verdicts | — |
| `policies/trivy` | Trivy scan policy (fail on CRITICAL) | `trivy` binary (via injected runner) |
| `policies/baseimage` | Base-image policy (UBI / Chainguard-Wolfi only) | `staging` filesystem access |
| `acr` | Outbound pusher to ACR using Managed Identity + go-containerregistry | Azure identity |
| `observability` | OTel metrics/traces setup, Prometheus `/metrics`, structured logging | OTel SDK |
| `audit` | Append-only decision + finding history writer (ClickHouse), behind a swappable interface | ClickHouse |
| `config` | Loads policy/severity/base-image/ACR/Entra/observability/audit config at startup | filesystem |

## 4. Push Data Flow & Lifecycle

1. **Auth** — Every `/v2/` request carries an Entra ID bearer token (Docker obtains
   it via the registry token flow). `auth` validates issuer, audience, signature
   (Entra JWKS), and expiry before any work. `GET /v2/` returns `401` with a
   `WWW-Authenticate` challenge to trigger the login flow.

2. **Blob upload** — Docker uploads each layer + config blob via
   `POST/PATCH/PUT /v2/<repo>/blobs/uploads/`. Merlin writes each blob into the
   staging store keyed by digest, verifying the digest on completion. No scan yet.

3. **Manifest PUT** — `PUT /v2/<repo>/manifests/<ref>` is the **completion signal**.
   Merlin now has every referenced blob in staging and assembles a complete OCI
   image (manifest + config + layers) in a local OCI layout.

4. **Policy gate** — Merlin hands the staged image to the `policy` engine, which
   runs all registered policies. Each returns a verdict. The gate aggregates:
   **all must pass**. All verdicts are collected (no short-circuit) so the developer
   sees every reason at once.

5. **Decision:**
   - **Pass** → `acr` pusher uploads the assembled image to ACR using Managed
     Identity; Merlin returns `201 Created` for the manifest — push succeeds.
   - **Fail** → Merlin returns an error status with a clear message listing failed
     policies and reasons. Staged content for this push is discarded.

6. **Cleanup** — Staging content removed after success or failure; a TTL sweep
   reclaims orphaned/abandoned uploads.

### Error handling principles

Infrastructure failures (Trivy crash, ACR unreachable) are distinct from policy
*failures*. Both block the push, but messaging and logging differ:
"scan could not complete" (infra) vs "image rejected: 2 CRITICAL CVEs" (policy).
Every decision is logged with the image digest, requesting identity, and per-policy
verdict for audit.

## 5. Policy Engine & v1 Policies

### Core interface

```go
// A Policy evaluates a staged image and returns a verdict.
type Policy interface {
    Name() string
    Evaluate(ctx context.Context, img StagedImage) (Verdict, error)
}

type Verdict struct {
    Passed  bool
    Reasons []string // human-readable, surfaced to docker push on failure
}
```

- `StagedImage` exposes the manifest, the config (layer history/labels), access to
  the assembled filesystem (for os-release reads), and the on-disk path Trivy scans.
- The **engine** holds an ordered list of registered policies, runs them, and returns
  `passed = AND(all verdicts)`. A returned `error` (vs a failed verdict) means the
  policy *could not run* — treated as a blocking infra failure, reported distinctly.
  The engine collects all verdicts; it does not stop at the first failure.

Adding a future check = implement `Policy` and register it. The gate is unchanged.

### v1 Policy 1 — `trivy`

- Runs Trivy against the staged image (local OCI layout, no network pull needed).
- Fails on any `CRITICAL` severity finding (v1 threshold). The threshold is read
  from config so it is tunable without code changes.
- Parses Trivy JSON output; on a CRITICAL finding, `Passed=false` with reasons like
  `CVE-2024-XXXX (CRITICAL) in openssl 1.1.1`.
- Invocation: shell out to the `trivy` binary (a documented dependency) via an
  injected runner interface so it is mockable in tests.

### v1 Policy 2 — `baseimage`

- Reads `/etc/os-release` (and `/etc/redhat-release`) from the assembled filesystem.
- Passes only if:
  - **RedHat UBI** — `os-release` has `ID="rhel"` / `PLATFORM_ID="platform:el*"` and
    `/etc/redhat-release` is present, **or**
  - **Chainguard/Wolfi** — `os-release` has `ID=wolfi` or `ID=chainguard`.
- Anything else → `Passed=false`, reason:
  `base image not permitted: detected <id>, allowed: rhel(ubi), wolfi/chainguard`.
- Accepted-base matchers are defined in config (extensible list of detection rules).

### Configuration (loaded at startup, e.g. YAML)

- Trivy severity threshold (default `CRITICAL`)
- Allowed base-image matchers
- ACR target (registry, repo mapping)
- Entra issuer / audience / JWKS endpoint

Keeping these in config means policy tuning does not require a rebuild.

## 6. Authentication

- **Inbound (developer → Merlin):** Entra ID bearer tokens. Devs `docker login` with
  their Entra identity; Merlin validates the token on every `/v2/` request.
- **Outbound (Merlin → ACR):** Merlin uses its own Azure Managed Identity / service
  principal. This is the only identity with write access to ACR, so the gate is the
  sole publish path — developers cannot bypass it.

## 7. Testing Strategy

TDD throughout (tests first), 80%+ coverage target. The `trivy` runner and `acr`
pusher sit behind interfaces so they are mockable.

**Unit tests:**
- `auth` — valid token passes; expired / wrong-audience / wrong-issuer /
  bad-signature / missing token rejected. Entra JWKS mocked.
- `staging` — blob write + digest verify (match stored, mismatch rejected), image
  assembly from staged blobs, cleanup/TTL sweep.
- `policy` engine — AND aggregation (all pass → pass; one fail → fail with all reasons
  collected); policy-error-vs-verdict distinction (error = blocking infra failure).
- `policies/trivy` — parse Trivy JSON: CRITICAL → fail with CVE reasons; only
  HIGH/MEDIUM → pass; configurable threshold honored. Trivy runner mocked.
- `policies/baseimage` — os-release fixtures: UBI passes, Wolfi/Chainguard passes,
  Debian/Ubuntu/Alpine fail, missing os-release fails.
- `audit` — decision + findings mapped to the correct rows/columns; batched writer
  flushes correctly; ClickHouse outage buffers and does not return an error to the
  caller (push not failed). ClickHouse client mocked.
- `observability` — metrics increment on the expected events; Trivy DB age metric
  reflects the scan's DB version.

**Integration tests:**
- `registryv2` — drive real V2 endpoints with an HTTP client mimicking docker's push
  sequence (POST/PATCH/PUT uploads → manifest PUT); assert status codes and staging
  contents.
- End-to-end gate (real Trivy binary, ACR mocked): good UBI image → forwarded; image
  with seeded CRITICAL CVE → rejected; Alpine-based image → rejected by base policy.
  ACR pusher replaced with a fake registry (go-containerregistry `httptest`).
- `audit` integration — write decision + findings to a real ClickHouse (test
  container), then exercise the reverse lookups (A: CVE → images; D: package/base;
  B: digest history; C: identity) and assert expected rows return.

**E2E (manual/CI smoke):** real `docker push` against a running Merlin pointed at a
test ACR — happy path and a rejection path.

## 9. Observability, Monitoring & Alerting

### Instrumentation (OTel-first)

- **Metrics** — OpenTelemetry metrics on a Prometheus `/metrics` endpoint;
  exportable to Azure Monitor. Core metrics: pushes received; gate decisions
  (pass/fail, by policy); scan duration histogram (→ p95); ACR push outcomes;
  Trivy DB age; in-flight staging size.
- **Logs** — Structured JSON to stdout with a stable schema; collected by the
  platform pipeline (Azure Monitor / Log Analytics).
- **Traces** — OTLP spans across the push lifecycle (auth → stage → scan → policy
  → ACR push) so a slow or failed push is debuggable end-to-end.

### Alert catalog

| Category | Alert | Priority |
|---|---|---|
| Freshness | Trivy vulnerability DB stale (scanning against an old DB = silently missed CVEs) | **Page** |
| Availability | Gate error rate high / unavailable (Trivy crash, ACR unreachable) | **Page** |
| Availability | ACR push failures *after* a pass (passed but could not publish) | High |
| Latency | Scan p95 too high (pushes timing out) | High |
| Security | Rejection-rate spike (possible misconfig or attack) | Medium |
| Security | Repeated rejections from one identity | Medium |

### Audit history — ClickHouse (append-only)

A dedicated `audit` emitter writes every gate decision to ClickHouse, behind an
interface so the store is swappable. Records are written on **every** decision —
pass *and* fail — so CVE lookups also cover successfully published images.

**`gate_decisions`** — one row per push (powers reverse lookups **B**, **C**):

```sql
ts             DateTime64,
push_id        UUID,
image_repo     String,
image_tag      String,
image_digest   String,
identity       String,
passed         Bool,
failed_policies Array(String),
reasons        Array(String),
base_image_id  String,
trivy_db_version String,
duration_ms    UInt32
ENGINE = MergeTree
ORDER BY (image_digest, ts)        -- fast digest history (B)
```

**`vulnerability_findings`** — one row per CVE per package per scan (powers **A**, **D**):

```sql
ts             DateTime64,
push_id        UUID,
image_digest   String,
image_repo     String,
cve_id         String,
severity       Enum8('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN'),
pkg_name       String,
pkg_version    String,
fixed_version  String,
base_image_id  String,
identity       String
ENGINE = MergeTree
ORDER BY (cve_id, severity, ts)    -- fast CVE → images reverse lookup (A)
```

**Reverse-lookup support (priority order):**

- **A — CVE → images:** `WHERE cve_id = ?` on `vulnerability_findings`
  (primary sort key → fast).
- **D — package / base → images:** filter `pkg_name` / `pkg_version` or
  `base_image_id`; secondary skip index or projection on `pkg_name`.
- **B — digest → decision history:** `gate_decisions` ordered by `image_digest`.
- **C — identity → activity:** filter `identity`; projection / skip index on
  `identity` in both tables.

**Write semantics:** audit writes are async and batched so ingestion never blocks
the push path. A ClickHouse outage degrades to buffered/queued writes plus an alert
— it does **not** fail the push. The gate decision is authoritative; the audit
record is a durable record of it.

## 10. Out of Scope (v1)

- Image signing / provenance (cosign) — future policy
- SBOM generation — future policy
- Non-root / config policies — future policy
- Pull-through / mirror behavior — Merlin gates pushes only
- Multi-backend support (ECR/GAR) — ACR only in v1
