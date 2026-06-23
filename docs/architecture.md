# Merlin — System Overview & Architecture

> Companion to [specs.md](./specs.md) (requirements) and [design.md](./design.md)
> (detailed design). This document gives the high-level shape: what Merlin is, how
> it is deployed, and how the major pieces fit together.

## 1. What Merlin Is

Merlin is a **transparent Docker Registry V2 proxy that gates image publishing**.
Developers push images with standard Docker tooling; Merlin buffers each image,
runs a security policy gate (Trivy vulnerability scan + base-image policy), and only
forwards passing images to the backend Azure Container Registry (ACR) dev repo.

Because Merlin's own service identity is the **only** identity with write access to
ACR, there is no path to publish an unscanned image. The gate is the sole publish
path.

```
docker push merlin.internal/<repo>:<tag>
        │
        ▼
   ┌─────────┐   pass    ┌──────────┐
   │ Merlin  │──────────►│   ACR    │
   │  gate   │           │ dev repo │
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
 └────────────┘             │  policy gate        │
                            │   ├─ trivy          │  scan      ┌──────────────┐
                            │   └─ baseimage      │            │ trivy binary │
                            │        │            │            │  + vuln DB   │
                            │        ▼  (pass)    │            └──────────────┘
                            │  acr pusher ────────┼──────────►┌──────────────┐
                            │   (Managed Identity)│           │     ACR      │
                            │        │            │           │  dev repo    │
                            │        ▼            │           └──────────────┘
                            │  observability ─────┼──────────►  Prometheus / Azure Monitor
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
| Trivy binary + vuln DB | Vulnerability scanning |
| ACR | Backend dev repository (write access only via Merlin) |
| ClickHouse | Append-only audit history + scan-report store |
| Prometheus / Azure Monitor | Metrics, alerting |

## 3. Component Map

Single Go binary; each package has one clear responsibility and a well-defined
interface (see [design.md](./design.md) for internals).

| Package | Responsibility |
|---|---|
| `router` | Maps event source → {ingress, outcome, gate profile}; drives the trigger-agnostic gate core (extension seam for new CI sources) |
| `ingress/docker` (`registryv2`) | Inbound Docker Registry V2 HTTP API; report endpoint — the v1 ingress adapter |
| `auth` | Entra ID bearer-token validation |
| `staging` | Buffered blob/manifest store (Blob + Valkey); image assembly |
| `policy` | Extensible gate engine; runs registered policies, aggregates verdicts |
| `policies/trivy` | Trivy scan policy (fail on CRITICAL) |
| `policies/baseimage` | Base-image policy (UBI / Chainguard-Wolfi only) |
| `acr` | Outbound pusher to ACR via Managed Identity |
| `observability` | OTel metrics/traces, Prometheus `/metrics`, structured logs |
| `audit` | Append-only decision + finding writer (ClickHouse) |
| `config` | Startup configuration loading |

### Extension seam (ports & adapters)

Merlin is built so its gate (acquire → scan → verdict → audit) is independent of
what triggers it. New CI integrations are added as **adapter pairs** registered in
the `router`, never by changing the gate core:

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

1. **Authenticate** — validate the Entra ID token on every `/v2/` request.
2. **Buffer** — accept parallel blob uploads into shared Blob staging; track
   session state in Valkey.
3. **Assemble** — on manifest PUT (completion signal), assemble the full image to
   local scratch.
4. **Gate** — run all policies; aggregate `passed = AND(verdicts)`.
5. **Publish or reject** — on pass, push to ACR with Managed Identity and return
   `201`; on fail, reject with a scan summary. Either way, emit metrics/traces and
   write the decision + findings to ClickHouse, and surface the Trivy scan result
   (summary inline + `X-Merlin-Scan-Report-URL`).

See [specs.md §4](./specs.md) for the detailed flow and error-handling principles.

## 5. Deployment & Scaling

- **N stateless replicas** behind a load balancer. All push state lives in shared
  backends (Blob + Valkey), so any replica serves any request of any push; a replica
  dying mid-push does not lose the push.
- **Horizontal scale** on CPU — Trivy scanning is the hot path.
- **Per-node protection** — blob uploads fan out freely (independent by upload UUID,
  tracked atomically in Valkey); scans fan in through a **bounded worker pool** with
  backpressure. Queue-depth and pool-utilization metrics drive autoscaling so the
  cluster adds replicas before nodes saturate.

See [specs.md §9](./specs.md) for the full scalability & concurrency model.

## 6. Security Posture

- **Inbound:** Entra ID identity required on every request.
- **Outbound:** Merlin's Managed Identity is the **only** writer to ACR — the gate
  cannot be bypassed.
- **Auditability:** every decision (pass and fail) and every vulnerability finding
  is recorded immutably in ClickHouse, supporting reverse lookups (CVE → images,
  package/base → images, digest history, identity activity).
- **Freshness:** a stale Trivy vulnerability DB is a paging alert — scanning against
  an old DB is treated as a silent security failure.

## 7. Observability at a Glance

- **Metrics** (Prometheus `/metrics`, exportable to Azure Monitor): pushes, gate
  decisions by policy, scan p95, ACR push outcomes, Trivy DB age, staging size.
- **Traces** (OTLP): auth → stage → scan → policy → ACR push per request.
- **Logs** (structured JSON): operational events, collected by the platform pipeline.
- **Audit** (ClickHouse): durable decision + finding history; also serves scan
  reports via `GET /reports/<push_id>`.

See [specs.md §8](./specs.md) for the alert catalog and audit schema.
