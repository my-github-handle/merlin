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
| `GET /token` | Docker token handshake — validates Entra credentials, mints a short-lived registry token (see [`auth`](#auth)) |
| `GET /v2/` | Version check; returns `401` + `WWW-Authenticate` (realm → `/token`) to trigger login |
| `POST /v2/<repo>/blobs/uploads/` | Begin a blob upload; returns a server-issued upload UUID + `Location` (monolithic `?digest=` also supported) |
| `PATCH /v2/<repo>/blobs/uploads/<uuid>` | Upload a chunk (`Content-Range`) |
| `PUT /v2/<repo>/blobs/uploads/<uuid>?digest=` | Complete a blob; verify digest |
| `HEAD /v2/<repo>/blobs/<digest>` | Blob existence check (dedupe) — `404` (push gate holds no blobs) |
| `HEAD/GET /v2/<repo>/manifests/<ref>` | Manifest existence check — `404` so the client proceeds with the push |
| `PUT /v2/<repo>/manifests/<ref>` | **Completion signal** — triggers the gate; echoes `Docker-Content-Digest` on success |
| `GET /reports/<push_id>` | Retrieve full Trivy JSON report from the audit store |

The handler is thin: it translates HTTP to `staging`/`policy`/`acr` calls and maps
verdicts to v2 error envelopes. No business logic lives here.

### `auth`

Merlin runs the standard Docker registry token handshake with a **clean separation**:
the `/token` endpoint is the sole Entra-validation point, and `/v2/` requests verify
only Merlin's own short-lived registry token.

```go
// Authenticator validates an Entra ID credential (used at the /token endpoint).
type Authenticator interface {
    // Validate returns the caller identity or an error if the token is invalid.
    Validate(ctx context.Context, bearer string) (Identity, error)
}

// RegistryTokenIssuer mints + verifies Merlin's own registry tokens (used on /v2/).
type RegistryTokenIssuer interface {
    Mint(subject, scope string) (token string, expiresIn int, err error)
    Verify(token string) (subject, scope string, err error)
}
```

- **At `/token`:** the developer's credential is validated against Entra ID — JWT
  signature against cached Entra JWKS (issuer, audience, expiry), with a fallback to
  the OAuth2 client-credentials grant for non-interactive callers. On success a
  registry token is minted (HMAC HS256, configurable TTL).
- **On `/v2/`:** the bearer is verified as a registry token (local HMAC check —
  issuer `merlin`, audience = service, expiry). Entra tokens are not accepted here.

Both the `Authenticator` and the issuer are injected into `registryv2`, so tests use
a fake authenticator and an in-process issuer.

### `staging`

Backs in-flight pushes on shared infrastructure so replicas are stateless.

```go
type Store struct { /* Blob + Valkey backends, behind BlobStore/SessionStore interfaces */ }

func (s *Store) BeginUpload(ctx context.Context, repo string) (uploadID string, err error)
func (s *Store) WriteChunk(ctx context.Context, uploadID string, offset int64, r io.Reader) (newOffset int64, err error)
func (s *Store) CompleteBlob(ctx context.Context, uploadID, digest string, r io.Reader) error
func (s *Store) PutManifest(ctx context.Context, repo, ref string, manifest []byte, configDigest string, layerDigests []string) (ManifestRef, error)
func (s *Store) Assemble(ctx context.Context, mr ManifestRef, scratchDir string) (policy.StagedImage, error)
func (s *Store) Cleanup(ctx context.Context, mr ManifestRef, scratchDir string) error
```

- **Blob payloads → Azure Blob Storage**, keyed by upload UUID (in flight) then by
  content digest (on completion). `CompleteBlob` verifies the digest before storing.
- **Session state → Valkey**: per-upload blob list, byte offsets, completion flags.
  Chunk ordering enforced with an **atomic compare-and-set on the offset**;
  out-of-order chunks rejected with `416`.
- `PutManifest` takes the config digest separately from the layer digests (the config
  is JSON, not a filesystem layer) and checks (atomically in Valkey) that every
  referenced blob is complete before producing a `ManifestRef`.
- `Assemble` reads the staged blobs into **local scratch** and produces two views:
  a valid **OCI image layout** (`oci-layout` + `index.json` + `blobs/sha256/`, with
  the index descriptor carrying the manifest's real media type) for `trivy image
  --input`, and an extracted **rootfs** for the base-image os-release check. Layers
  are gunzipped (real layers are `tar+gzip`) before extraction; the config blob is
  placed in the layout verbatim, never tar-extracted. Scratch is reclaimed after
  scanning; a TTL sweep reclaims abandoned uploads.

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

- Reads `os-release` from the assembled filesystem — `/etc/os-release` first, then
  `/usr/lib/os-release` (UBI/Chainguard symlink `/etc/os-release` →
  `../usr/lib/os-release`, and layer extraction skips symlinks, so only the
  `/usr/lib` copy lands in the rootfs).
- Passes only when the parsed `ID` is in the configured allow-list — by default
  **RedHat UBI** (`ID=rhel`) or **Chainguard/Wolfi** (`ID=wolfi`/`ID=chainguard`).
- Otherwise fails with `base image not permitted: detected <id>, allowed: rhel,
  wolfi, chainguard`.
- The allowed-ID set is config-driven (`baseImage.allowedIDs`) and matched
  case-insensitively.

### `acr`

```go
type Pusher interface {
    Push(ctx context.Context, ociPath, target string) error
}
```

Pushes the assembled OCI layout to ACR using `go-containerregistry`, authenticating
with Azure Workload Identity (AAD token exchanged for an ACR refresh token). Behind
an interface so tests use a fake registry (go-containerregistry `httptest`).

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
