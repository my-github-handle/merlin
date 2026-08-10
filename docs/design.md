# Merlin — Detailed Design

> Companion to [specs.md](./specs.md) (requirements) and
> [architecture.md](./architecture.md) (high-level overview). This document details
> package internals, interfaces, data flow, and key implementation decisions.

## 1. Package Design

Each package is independently testable with a clear interface. Dependencies flow
inward toward `policy` and `staging`; external systems (Grype, ACR, Blob, Valkey,
ClickHouse, Entra) sit behind interfaces so they are mockable. `app` wires
everything: `Build` returns a hermetic instance for tests (stub auth, no backends);
`BuildWithBackends` wires live JWKS, Blob, Valkey, ClickHouse, per-tenant ACR
pushers, and the dashboard.

### `router`

The trigger-agnostic gate core. The router is outcome-agnostic: it runs the policy
engine over a normalized, source-agnostic request and returns the result by value
(request-local, no shared state); the source-specific handler decides how to act.

```go
// GateRequest is a normalized request to gate an artifact, source-agnostic.
type GateRequest struct {
    Source   string             // e.g. "docker"
    Identity string             // authenticated pusher identity
    Image    policy.StagedImage // assembled image on scratch
    Target   string             // destination reference in the tenant's ACR
}

// Gate runs the policy engine and returns the gate result plus any infra error.
func (r *Router) Gate(ctx context.Context, req GateRequest) (policy.Result, error)
```

`router.Pool` is a semaphore that bounds concurrent scans (`scan_pool_size`).
Slot wait and scan run on **separate budgets** (`Acquire` + `Router().Gate`): queue
time never consumes scan time. A wait deadline expiry returns `ErrSaturated`
(mapped to `503` + `Retry-After` and recorded as an infra-error decision); a
client disconnect while queued is distinguished from saturation.

v1 has exactly one adapter pair — the Docker ingress (`docker.Handler`) and outcome
(`docker.Outcome`), both in `ingress/docker`. The `github` and `api` adapters are
designed-for and deferred (see [specs.md §10–11](./specs.md)); adding one means
building a new ingress/outcome pair around `Router.Gate`, not changing the core.

### `ingress/docker` (`registryv2`)

The v1 adapter pair. Implements the inbound Docker Registry V2 HTTP surface plus a
report endpoint; the paired `Outcome` (same package) blocks the push or forwards to
ACR. Every request is first resolved to a **tenant** by host (see [`tenant`](#tenant));
unknown hosts get `404` before auth.

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
| `GET /reports/<push_id \| repo:tag \| repo@digest>` | Retrieve the scan report (findings + age) from the audit store |

Manifest PUTs are **classified** (`classify.go`): plain image manifests are gated;
image indexes (manifest lists) and buildx attestation manifests (all layers
`application/vnd.in-toto+json`) are forwarded to ACR verbatim via `PushManifest`
(attestation blobs seeded first via `PushBlob`). Ordering is enforced by ACR
itself — an index PUT fails unless its referenced (gated) image manifest already
exists, so a rejected image cannot be published by reference.

The handler is thin: it translates HTTP to `staging`/`policy`/`acr` calls and maps
verdicts to v2 error envelopes. No business logic lives here. `Outcome.Apply` maps
the gate result to the response: pass → ACR push → `201`; policy fail → `400`;
infra error → `500`; ACR push failure → `502`; scan-pool saturation → `503`.

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
// The minted token carries the tenant prefix as a claim; /v2/ rejects a token
// whose prefix does not match the request host's tenant.
func (i *RegistryTokenIssuer) Mint(subject, scope, prefix string) (token string, expiresIn int, err error)
func (i *RegistryTokenIssuer) Verify(token string) (subject, scope, prefix string, err error)
```

- **At `/token`:** the developer's credential is validated against Entra ID — JWT
  signature against cached Entra JWKS (issuer, audience, expiry), with a fallback to
  the OAuth2 client-credentials grant for non-interactive callers. On success a
  registry token is minted (HMAC HS256, configurable TTL).
- **On `/v2/`:** the bearer is verified as a registry token (local HMAC check —
  issuer `merlin`, audience = service, expiry). Entra tokens are not accepted here.

Both the `Authenticator` and the issuer are injected into `registryv2`, so tests use
a fake authenticator and an in-process issuer.

### `tenant`

Maps an inbound request host to the ACR tenant that serves it — the multi-tenant
security boundary.

```go
// Tenant bundles everything that was single-valued in the single-registry design.
type Tenant struct {
    Prefix   string             // DNS label, e.g. "c3devops"
    Registry string             // resolved ACR host from acr.registry_template
    Pusher   acr.Pusher         // per-tenant workload-identity pusher
    Authn    auth.Authenticator // per-tenant Entra validation (issuer/audience/JWKS)
}

// Resolver maps a request host to its tenant.
type Resolver interface {
    ForHost(host string) (*Tenant, bool)
}
```

The static resolver takes the single leading DNS label before `base_domain` as the
prefix (`<prefix>.<baseDomain>`); an unknown or malformed host resolves to nothing
and the handler returns `404` before any authentication runs.

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
  content digest (on completion, `blob/<digest>`). `CompleteBlob` verifies the
  digest before storing. Completed blobs are **content-addressed and ref-counted**
  in Valkey (`IncBlobRef`/`DecBlobRef`) so concurrent pushes can share layers.
- **Session state → Valkey**: per-upload blob list, byte offsets, completion flags.
  Chunk ordering enforced with an **atomic compare-and-set on the offset**;
  out-of-order chunks rejected with `416`.
- `PutManifest` takes the config digest separately from the layer digests (the config
  is JSON, not a filesystem layer) and checks (atomically in Valkey) that every
  referenced blob is complete before producing a `ManifestRef`.
- `Assemble` reads the staged blobs into **local scratch** and produces two views:
  a valid **OCI image layout** (`oci-layout` + `index.json` + `blobs/sha256/`, with
  the index descriptor carrying the manifest's real media type) for the Grype scan,
  and an extracted **rootfs** for the base-image os-release check. Layers are
  gunzipped (real layers are `tar+gzip`) before extraction; symlinks, hardlinks,
  and device nodes are skipped as escape-surface reduction; the config blob is
  placed in the layout verbatim, never tar-extracted. `Assemble` also extracts the
  image config `created` timestamp for the image-age policy. `Cleanup` reclaims
  scratch after scanning and deletes staged blobs only when their ref-count
  reaches zero.

### `policy`

The extensible gate engine.

```go
type Policy interface {
    Name() string
    Evaluate(ctx context.Context, img StagedImage) (Verdict, error)
}

type Verdict struct {
    Passed           bool
    Reasons          []string
    Findings         []Finding // scanner findings (set by the grype policy)
    ScannerDBVersion string
    Age              *AgeInfo  // set by the image-age policy; nil for other policies
}

type Engine struct { policies []Policy }

// Run executes all policies, collects all verdicts (no short-circuit), and
// returns aggregate pass = AND(verdicts). A returned error from any policy is a
// blocking infra failure, reported distinctly from a clean reject.
func (e *Engine) Run(ctx context.Context, img StagedImage) (Result, error)
```

`Result` carries the aggregate pass/fail, per-policy verdicts, the structured
scanner findings, the scanner DB version, and the image-age info (for the response
summary and audit). Adding a future check = implement `Policy` and register it; the
engine is unchanged.

### `policies/grype`

```go
type Runner interface { // injected, mockable
    Scan(ctx context.Context, ociPath string) (Report, error)
}
```

- Default `Runner` shells out to the `grype` binary against the local OCI layout
  (`grype <ociPath> -o json -q --by-cve`), parsing JSON output into `Report`
  (findings + scanner DB version).
- Fails on any finding at or above the configured threshold (default `CRITICAL`);
  **fails closed** on unrecognized severities.
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
- The allowed-ID set is config-driven (`base_image.allowed_ids`) and matched
  case-insensitively.

### `policies/imageage`

```go
// Rule is the per-tenant age configuration.
type Rule struct {
    Enabled       bool
    ThresholdDays int
}
```

- Rejects images whose config `created` timestamp is older than the threshold
  (default 60 days). A default rule applies to any tenant without an explicit
  per-tenant override (`tenants[].image_age`).
- **Fails closed**: a zero/unreadable `created` timestamp is a reject, not a pass.
- The computed age is returned on the `Verdict` (`AgeInfo`) for response + audit.

### `acr`

```go
type Pusher interface {
    // Push uploads a gated image from a local OCI layout to target.
    Push(ctx context.Context, ociPath, target string) error
    // PushManifest uploads a raw manifest (or index) verbatim, preserving its
    // exact bytes and content digest (indexes, buildx attestations).
    PushManifest(ctx context.Context, raw []byte, mediaType, target string) error
    // PushBlob seeds a content blob an attestation manifest references.
    PushBlob(ctx context.Context, raw []byte, mediaType, repo string) error
}
```

Pushes the assembled OCI layout to ACR using `go-containerregistry`, authenticating
with Azure Workload Identity (AAD token exchanged for an ACR refresh token, cached
until the refresh token's own expiry). Each tenant gets its own pusher bound to its
ACR client ID. Behind an interface so tests use a fake registry
(go-containerregistry `httptest`).

### `observability`

Prometheus metrics (served on the metrics port, default `:9090`) and structured
logging: `merlin_push_decisions_total`, `merlin_scan_duration_seconds`,
`merlin_scanner_db_age_days` (from each scan's reported DB version),
`merlin_acr_push_total`. OTel traces are designed-for but deferred.

### `audit`

```go
// Writer is the storage backend (ClickHouse in production).
type Writer interface {
    Write(ctx context.Context, d Decision, findings []policy.Finding) error
}

// Auditor wraps a Writer in an async bounded queue; Record never blocks.
func (a *Auditor) Record(ctx context.Context, d Decision, findings []policy.Finding)
```

- Writes to ClickHouse: `gate_decisions` (one row per push), `vulnerability_findings`
  (one row per CVE/package/scan), and `tag_aliases` (tag → digest, recorded when a
  buildx index is forwarded by tag), on **every** decision. The schema is
  self-bootstrapped at startup with TTL-based retention (`audit.retention_days`,
  default 30). A decision carries `infra_error` + `error_detail` when the gate did
  **not** complete (scan timeout, assemble/ACR failure) — distinct from a policy
  rejection, so an unfinished scan is explainable from the audit store.
- **Async + non-blocking** so ingestion never blocks the push path. Writes queue in
  a bounded buffer (`audit.queue_size`) drained by a worker with a per-write
  timeout and bounded retries + backoff; on overflow or final write failure the
  record is dropped and an `onDrop` alert fires — a ClickHouse outage does **not**
  fail the push.
- A `Reader` serves `GET /reports/...` (by push ID, `repo:tag`, or digest — tag refs
  resolve through `tag_aliases` for buildx pushes) and the dashboard queries. Query
  errors are surfaced as "report unavailable", never masked as "not found".

### `dashboard`

Read-only observability UI served on its own port (default `:8080`, `off` to
disable). Routes: `/` (overview), `/report`, `/api/dashboard/images`,
`/api/dashboard/report.json`, `/api/dashboard/stream` (SSE live feed), `/static/`.
A `TeeRecorder` fans each gate decision into both the `Auditor` and an in-process
`Broadcaster` so connected dashboards see decisions live; historical views come
from the ClickHouse `Reader`.

### `config`

Loads a single YAML file at startup (path from `MERLIN_CONFIG`): Grype severity
threshold, base-image allow-list, image-age rules (default + per-tenant), ACR
`registry_template` (must contain `{prefix}`) + `base_domain`, tenants (prefix,
ACR client ID, Entra issuer/audience/JWKS/tenant ID), registry-token secret + TTL,
Blob/Valkey/ClickHouse connection settings, scan-pool size, and server settings
(addresses, external URL, max upload bytes, gate/shutdown timeouts). `${ENV}`
references are expanded **strictly** — any unset variable fails startup (used for
`REGISTRY_TOKEN_SECRET` and `CLICKHOUSE_PASSWORD`). `MERLIN_MODE=production`
selects `app.BuildWithBackends`; anything else builds the hermetic instance.

## 2. Data Flow

```
tenant resolve ──► auth ──► staging (Blob + Valkey) ──[manifest PUT]──► classify
                                                          │
                              index / attestation ◄───────┤ image
                              (forward verbatim)          ▼
                                                    assemble to scratch
                                                          │
                                                          ▼
                                              scan pool ► policy.Engine.Run
                                                    ├─ grype.Evaluate
                                                    ├─ baseimage.Evaluate
                                                    └─ imageage.Evaluate
                                                          │
                                   pass ◄─────────────────┴──────────────► fail
                                    │                                        │
                              acr.Push ──► tenant ACR                  reject + cleanup
                                    │                                        │
                                    └──► observability + audit + dashboard ◄─┘
                                         (both paths; response carries
                                          scan summary + report URL)
```

## 3. Key Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Gate timing | Buffer-and-hold (synchronous) | Only model that blocks publish until pass |
| Grype invocation | Shell out to binary | Simplest; always-current DB; mockable via Runner |
| Base detection | os-release inspection | Intrinsic to base; survives registry path / version drift |
| Image freshness | Config `created` timestamp, fail closed | Intrinsic to image; missing timestamp is suspicious |
| Multi-tenancy | Host prefix → tenant (registry, pusher, auth) | One deployment serves many ACRs; host binding is the security boundary |
| Index/attestation handling | Forward verbatim, rely on ACR ordering | Preserves digests; rejected images can't be published by reference |
| Staging backend | Azure Blob + Valkey (ref-counted blobs) | Stateless replicas; true horizontal scaling |
| Scan concurrency | Bounded worker pool + backpressure | Scanning is CPU/mem heavy; protects the node |
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
