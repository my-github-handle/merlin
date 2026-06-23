# Merlin — Detailed Design

> Companion to [specs.md](./specs.md) (requirements) and
> [architecture.md](./architecture.md) (high-level overview). This document details
> package internals, interfaces, data flow, and key implementation decisions.

## 1. Package Design

Each package is independently testable with a clear interface. Dependencies flow
inward toward `policy` and `staging`; external systems (Trivy, ACR, Blob, Valkey,
ClickHouse, Entra) sit behind interfaces so they are mockable.

### `router`

The extension seam (ports & adapters). Maps an event source to the adapter pair and
gate profile that handle it, then drives the trigger-agnostic gate core. Adding a CI
integration is "register an adapter pair," not a core change.

```go
type Ingress interface {
    // Acquire turns an inbound event into a staged artifact + request context.
    Acquire(ctx context.Context, event Event) (GateRequest, error)
}

type Outcome interface {
    // Apply acts on the verdict in the way appropriate to the source.
    Apply(ctx context.Context, req GateRequest, result policy.Result) error
}

type Route struct {
    Ingress Ingress
    Outcome Outcome
    Profile GateProfile // which policies/thresholds apply for this source
}

// Handle: acquire → gate core (staging → policy.Engine.Run → audit) → outcome.Apply
func (r *Router) Handle(ctx context.Context, source string, event Event) error
```

v1 registers exactly one route: `docker → {ingress/docker, outcome/docker}`. The
`github` and `api` adapters are designed-for and deferred (see [specs.md §10–11](./specs.md)).

### `ingress/docker` (`registryv2`)

The v1 ingress adapter. Implements the inbound Docker Registry V2 HTTP surface plus a
report endpoint. Its `Acquire` is the push itself (Docker streams blobs into
staging); its paired `outcome/docker` blocks the push or forwards to ACR.

| Endpoint | Purpose |
|---|---|
| `GET /v2/` | Version check; returns `401` + `WWW-Authenticate` to trigger login |
| `POST /v2/<repo>/blobs/uploads/` | Begin a blob upload; returns a server-issued upload UUID + `Location` |
| `PATCH /v2/<repo>/blobs/uploads/<uuid>` | Upload a chunk (`Content-Range`) |
| `PUT /v2/<repo>/blobs/uploads/<uuid>?digest=` | Complete a blob; verify digest |
| `HEAD /v2/<repo>/blobs/<digest>` | Blob existence check (dedupe) |
| `PUT /v2/<repo>/manifests/<ref>` | **Completion signal** — triggers the gate |
| `GET /reports/<push_id>` | Retrieve full Trivy JSON report from the audit store |

The handler is thin: it translates HTTP to `staging`/`policy`/`acr` calls and maps
verdicts to v2 error envelopes. No business logic lives here.

### `auth`

```go
type Authenticator interface {
    // Validate returns the caller identity or an error if the token is invalid.
    Validate(ctx context.Context, bearer string) (Identity, error)
}
```

Validates Entra ID JWTs: signature against cached Entra JWKS, issuer, audience,
expiry. JWKS fetch is cached with refresh. Injected into `registryv2` so tests use a
fake authenticator.

### `staging`

Backs in-flight pushes on shared infrastructure so replicas are stateless.

```go
type Store interface {
    BeginUpload(ctx context.Context, repo string) (uploadID string, err error)
    WriteChunk(ctx context.Context, uploadID string, offset int64, r io.Reader) (newOffset int64, err error)
    CompleteBlob(ctx context.Context, uploadID, digest string) error
    PutManifest(ctx context.Context, repo, ref string, manifest []byte) (StagedImage, error)
    Assemble(ctx context.Context, img StagedImage) (localPath string, err error) // to scratch for scanning
    Cleanup(ctx context.Context, pushID string) error
}
```

- **Blob payloads → Azure Blob Storage**, keyed by upload UUID.
- **Session state → Valkey**: per-upload blob list, byte offsets, completion flags.
  Chunk ordering enforced with an **atomic compare-and-set on the offset**;
  out-of-order chunks rejected with `416`.
- `PutManifest` checks (atomically in Valkey) that every referenced blob digest is
  marked complete before producing a `StagedImage`.
- `Assemble` streams the image from Blob to **local scratch** (Trivy needs a local
  path); scratch is reclaimed after scanning. A TTL sweep reclaims abandoned uploads.

### `policy`

The extensible gate engine.

```go
type Policy interface {
    Name() string
    Evaluate(ctx context.Context, img StagedImage) (Verdict, error)
}

type Verdict struct {
    Passed  bool
    Reasons []string
}

type Engine struct { policies []Policy }

// Run executes all policies, collects all verdicts (no short-circuit), and
// returns aggregate pass = AND(verdicts). A returned error from any policy is a
// blocking infra failure, reported distinctly from a clean reject.
func (e *Engine) Run(ctx context.Context, img StagedImage) (Result, error)
```

`Result` carries the aggregate pass/fail, per-policy verdicts, and the structured
Trivy findings (for the response summary and audit). Adding a future check =
implement `Policy` and register it; the engine is unchanged.

### `policies/trivy`

```go
type Runner interface { // injected, mockable
    Scan(ctx context.Context, imagePath string) (Report, error)
}
```

- Default `Runner` shells out to the `trivy` binary against the local scratch path,
  parsing JSON output into `Report` (findings + scanned DB version).
- Fails on any finding at or above the configured threshold (default `CRITICAL`).
- Reasons formatted as `CVE-2024-XXXX (CRITICAL) in openssl 1.1.1`.
- The full `Report` is returned in the `Verdict`/`Result` for response + audit.

### `policies/baseimage`

- Reads `/etc/os-release` and `/etc/redhat-release` from the assembled filesystem.
- Passes only for **RedHat UBI** (`ID="rhel"` / `PLATFORM_ID="platform:el*"` +
  `redhat-release` present) or **Chainguard/Wolfi** (`ID=wolfi`/`ID=chainguard`).
- Otherwise fails with `base image not permitted: detected <id>, allowed: rhel(ubi),
  wolfi/chainguard`.
- Matchers are config-driven (an extensible list of detection rules).

### `acr`

```go
type Pusher interface {
    Push(ctx context.Context, img StagedImage, target string) error
}
```

Pushes the assembled image to ACR using `go-containerregistry` with Azure Managed
Identity. Behind an interface so tests use a fake registry (go-containerregistry
`httptest`).

### `observability`

Sets up OTel metrics + traces, exposes Prometheus `/metrics`, and provides the
structured logger. Instruments the push lifecycle (auth → stage → scan → policy →
ACR push). Tracks the Trivy DB age metric from each scan's reported DB version.

### `audit`

```go
type Auditor interface {
    Record(ctx context.Context, decision Decision, findings []Finding) // async, non-blocking
}
```

- Writes to ClickHouse: `gate_decisions` (one row per push) and
  `vulnerability_findings` (one row per CVE/package/scan), on **every** decision.
- **Async + batched** so ingestion never blocks the push path. A ClickHouse outage
  buffers writes and raises an alert; it does **not** fail the push.
- Also serves `GET /reports/<push_id>` by reading findings back from ClickHouse.

### `config`

Loads YAML at startup: Trivy threshold, base-image matchers, ACR target, Entra
issuer/audience/JWKS, Blob/Valkey/ClickHouse connection settings, scan-pool size.

## 2. Data Flow

```
auth ──► staging (Blob + Valkey) ──[manifest PUT]──► assemble to scratch
                                                          │
                                                          ▼
                                                    policy.Engine.Run
                                                    ├─ trivy.Evaluate
                                                    └─ baseimage.Evaluate
                                                          │
                                   pass ◄─────────────────┴──────────────► fail
                                    │                                        │
                              acr.Push ──► ACR                         reject + cleanup
                                    │                                        │
                                    └──────────► observability + audit ◄─────┘
                                                 (both paths; response carries
                                                  scan summary + report URL)
```

## 3. Key Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Gate timing | Buffer-and-hold (synchronous) | Only model that blocks publish until pass |
| Trivy invocation | Shell out to binary | Simplest; always-current DB; mockable via Runner |
| Base detection | os-release inspection | Intrinsic to base; survives registry path / version drift |
| Staging backend | Azure Blob + Valkey | Stateless replicas; true horizontal scaling |
| Scan concurrency | Bounded worker pool + backpressure | Trivy is CPU/mem heavy; protects the node |
| Audit store | ClickHouse, append-only | Columnar speed for CVE → image reverse lookups |
| Audit write failure | Non-blocking (buffer + alert) | Publish availability not coupled to ClickHouse |
| Scan result delivery | Summary inline + report URL header | Works within what `docker push` renders |
| CI extensibility | Router + ingress/outcome adapters | New sources (GitHub, API) without touching the gate core |

## 4. Testing

See [specs.md §7](./specs.md) for the full strategy. Summary: TDD throughout, 80%+
coverage; every external system (`auth`, `Runner`, `Pusher`, `staging` backends,
`audit`) is behind an interface and mocked in unit tests; integration tests drive
the real V2 endpoints and a real ClickHouse (test container) to exercise reverse
lookups; E2E does a real `docker push` against a running instance.
