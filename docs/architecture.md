# Merlin — System Overview & Architecture

> Companion to [specs.md](./specs.md) (requirements) and [design.md](./design.md)
> (detailed design). This document gives the high-level shape: what Merlin is, how
> it is deployed, and how the major pieces fit together.

## 1. What Merlin Is

Merlin is a **transparent Docker Registry V2 proxy that gates image publishing**.
Developers push images with standard Docker tooling; Merlin buffers each image,
runs a security policy gate (Grype vulnerability scan + base-image policy +
image-age policy), and only forwards passing images to the tenant's backend Azure
Container Registry (ACR).

Merlin is **multi-tenant**: the request host's DNS prefix (`<prefix>.<baseDomain>`)
selects the tenant — its target ACR, its outbound push identity, and its inbound
auth surface. Because Merlin's per-tenant workload identities are the **only**
identities with write access to each ACR, there is no path to publish an unscanned
image. The gate is the sole publish path.

```
docker push <prefix>.<baseDomain>/<repo>:<tag>
        │
        ▼
   ┌─────────┐   pass    ┌──────────┐
   │ Merlin  │──────────►│  tenant  │
   │  gate   │           │   ACR    │
   └─────────┘           └──────────┘
        │ fail
        ▼
   rejected (with scan summary)
```

## 2. System Context

```
   Developers                Merlin (N replicas)              Backends
 ┌────────────┐   docker    ┌────────────────────┐
 │  docker    │── push ────►│  registryv2 / auth │
 │  CLI       │  (Entra ID) │        │            │
 └────────────┘             │        ▼            │   blobs   ┌──────────────┐
                            │  staging ───────────┼──────────►│ Azure Blob   │
 ┌────────────┐  Entra ID   │        │            │  session  ┌──────────────┐
 │  Entra ID  │◄── validate │        │            │──────────►│   Valkey     │
 │  (JWKS)    │             │        ▼            │           └──────────────┘
                            │  policy gate        │
                            │   ├─ grype          │  scan      ┌──────────────┐
                            │   ├─ baseimage      │            │ grype binary │
                            │   └─ imageage       │            │  + vuln DB   │
                            │        ▼  (pass)    │            └──────────────┘
                            │  acr pusher ────────┼──────────►┌──────────────┐
                            │  (Workload Identity,│           │  tenant ACR  │
                            │      per tenant)    │           │ (per prefix) │
                            │        ▼            │           └──────────────┘
                            │  observability ─────┼──────────►  Prometheus / Azure Monitor
                            │  dashboard :8080 ───┼──────────►  read-only UI + SSE live feed
                            │  audit ─────────────┼──────────►┌──────────────┐
                            └────────────────────┘           │  ClickHouse  │
                                                              └──────────────┘
```

**External dependencies:**

| Dependency | Role |
|---|---|
| Entra ID (JWKS) | Validates developer identity on inbound pushes |
| Azure Blob Storage | Shared buffered staging for in-flight blobs |
| Valkey | Shared upload-session state (blob list, offsets, completion) |
| Grype binary + vuln DB | Vulnerability scanning |
| ACR (one per tenant) | Backend repository (write access only via Merlin) |
| ClickHouse | Append-only audit history + scan-report store |
| Prometheus / Azure Monitor | Metrics, alerting |

## 3. Component Map

Single Go binary; each package has one clear responsibility and a well-defined
interface (see [design.md](./design.md) for internals).

| Package | Responsibility |
|---|---|
| `app` | Wiring/DI: `Build` (hermetic, for tests) and `BuildWithBackends` (production — live JWKS, Blob, Valkey, ClickHouse, per-tenant ACR pushers, dashboard) |
| `router` | Drives the trigger-agnostic gate core (`Gate`) and bounds scan concurrency (`Pool` + backpressure); extension seam for new CI sources |
| `tenant` | Maps request host (`<prefix>.<baseDomain>`) → tenant {ACR target, pusher, auth surface} — the multi-tenant security boundary |
| `ingress/docker` (`registryv2`) | Inbound Docker Registry V2 HTTP API; manifest classification (image / index / attestation); report endpoint; outcome adapter (push-or-reject) — the v1 adapter pair |
| `auth` | Docker token handshake — Entra validation at `/token`, mints/verifies Merlin's short-lived registry token (carrying the tenant prefix) used on `/v2/` |
| `staging` | Buffered blob/manifest store (Blob + Valkey); content-addressed ref-counted blobs; image assembly |
| `policy` | Extensible gate engine; runs registered policies, aggregates verdicts |
| `policies/grype` | Grype scan policy (fail at/above configured severity threshold, default CRITICAL) |
| `policies/baseimage` | Base-image policy (os-release `ID` allow-list) |
| `policies/imageage` | Image freshness policy (max age in days from the image config `created` timestamp; per-tenant rules; fails closed) |
| `acr` | Outbound pusher to ACR via Azure Workload Identity (`Push`, `PushManifest`, `PushBlob`) |
| `observability` | Prometheus `/metrics`, structured logs |
| `audit` | Append-only decision + finding writer/reader (ClickHouse, self-bootstrapped schema, TTL retention) |
| `dashboard` | Read-only observability UI (`:8080`): overview, per-push reports, JSON API, SSE live feed |
| `config` | Startup configuration loading (YAML + strict `${ENV}` expansion) |

### Extension seam (ports & adapters)

Merlin is built so its gate (acquire → scan → verdict → audit) is independent of
what triggers it. The `router` gate core is outcome-agnostic; the Docker ingress
and outcome adapters live in `ingress/docker`. New CI integrations are added as
**adapter pairs** around that core, never by changing the gate core:

```
 ingress adapters          gate core (unchanged)        outcome adapters
 ┌──────────────┐                                       ┌──────────────────┐
 │ docker (v1)  │─┐                                    ┌─│ docker: block /  │
 │ github  (●)  │─┼─► staging ─► policy.Engine ─► audit─┼─│   forward to ACR │
 │ api     (●)  │─┘            (verdict)                └─│ github: check-run(●)│
 └──────────────┘                                       │ api: verdict JSON (●)│
                                                         └──────────────────┘
   (●) = designed-for, deferred past v1
```

Docker is synchronous (block in-band); future webhook/API ingresses are asynchronous
(report a verdict, e.g. a GitHub check-run). That difference lives in the adapters —
the core is unaffected. See [specs.md §10](./specs.md).

## 4. Request Lifecycle (high level)

1. **Resolve tenant** — the request host's prefix selects the tenant (ACR target,
   pusher identity, auth surface); unknown hosts get `404` before auth.
2. **Authenticate** — Docker runs the registry token handshake: it presents the
   developer's Entra credential to `GET /token` (the sole Entra-validation point),
   which mints a short-lived registry token bound to the tenant prefix; every
   `/v2/` request is then authorized by verifying that registry token (a token for
   another tenant is rejected). See [specs.md §6](./specs.md).
3. **Buffer** — accept parallel blob uploads into shared Blob staging; track
   session state in Valkey.
4. **Classify & assemble** — on manifest PUT (completion signal), classify the
   manifest: image indexes and buildx attestation manifests are forwarded to ACR
   verbatim (ACR's own ordering guarantees a rejected image can't be published by
   reference); image manifests are assembled to local scratch for gating.
5. **Gate** — run all policies (Grype, base-image, image-age; no short-circuit);
   aggregate `passed = AND(verdicts)`.
6. **Publish or reject** — on pass, push to the tenant's ACR with Workload Identity
   and return `201`; on fail, reject with `400` and a scan summary. Either way,
   emit metrics, write the decision + findings to ClickHouse (async), tee to the
   dashboard live feed, and surface the scan result (summary inline +
   `X-Merlin-Scan-Report-URL`).

See [specs.md §4](./specs.md) for the detailed flow and error-handling principles.

## 5. Deployment & Scaling

- **N stateless replicas** behind a load balancer. All push state lives in shared
  backends (Blob + Valkey), so any replica serves any request of any push; a replica
  dying mid-push does not lose the push.
- **Horizontal scale** on CPU — Grype scanning is the hot path.
- **Per-node protection** — blob uploads fan out freely (independent by upload UUID,
  tracked atomically in Valkey); scans fan in through a **bounded worker pool** with
  backpressure. Queue-depth and pool-utilization metrics drive autoscaling so the
  cluster adds replicas before nodes saturate.

See [specs.md §9](./specs.md) for the full scalability & concurrency model.

## 6. Security Posture

- **Inbound:** Entra ID identity required — validated once at `/token`, which mints a
  short-lived registry token that `/v2/` requests must present.
- **Tenant isolation:** the host → tenant binding is the security boundary — unknown
  hosts are rejected before auth, and a registry token minted for one tenant is
  rejected on another tenant's host (`prefix` claim check).
- **Outbound:** Merlin's per-tenant Azure Workload Identities are the **only**
  writers to each ACR — the gate cannot be bypassed.
- **Auditability:** every decision (pass and fail) and every vulnerability finding
  is recorded immutably in ClickHouse, supporting reverse lookups (CVE → images,
  package/base → images, digest history, identity activity).
- **Freshness:** a stale Grype vulnerability DB is a paging alert — scanning against
  an old DB is treated as a silent security failure. The image-age policy also
  rejects images built from configs older than the tenant's threshold.

## 7. Observability at a Glance

- **Metrics** (Prometheus `/metrics` on `:9090`, exportable to Azure Monitor):
  `merlin_push_decisions_total`, `merlin_scan_duration_seconds`,
  `merlin_scanner_db_age_days`, `merlin_acr_push_total`,
  `merlin_scan_cache_total` (reuse hit/miss; both series always present).
- **Logs** (structured JSON): operational events, collected by the platform pipeline.
- **Dashboard** (`:8080`): read-only overview + per-push report UI, JSON API, and an
  SSE live feed of gate decisions.
- **Audit** (ClickHouse): durable decision + finding history; also serves scan
  reports via `GET /reports/<push_id | repo:tag | repo@digest>`.

See [specs.md §8](./specs.md) for the alert catalog and audit schema.
