# Multi-ACR Tenant Routing — Design

**Date:** 2026-06-26
**Status:** Approved (pending spec review)

## Problem

Merlin currently gates pushes into a single ACR (`acr.registry`) with a single
inbound auth surface (`auth.issuer`/`audience`/`jwks_url`) and a single outbound
push identity (`DefaultAzureCredential`). We need to support multiple ACRs
selected by the **DNS subdomain prefix** the client connects to, e.g.:

- `c3dev.c3ci.cloud`  → `c3devacr.azurecr.io`
- `c3prod.c3ci.cloud` → `c3prodacr.azurecr.io`

Each prefix is an isolated tenant: its own inbound Entra identity, its own
outbound ACR push (workload) identity, and its own target ACR. One Merlin
deployment serves all prefixes; DNS names point at the same service.

## Decisions (from brainstorming)

| Question | Decision |
|---|---|
| Routing key | **Host subdomain prefix** — strip the shared base domain, leading label is the prefix |
| Prefix → ACR | **Template/pattern** — `{prefix}` substituted into `acr.registry_template` |
| Outbound ACR auth | **Per-prefix workload identity** (secretless, federated; per-prefix client ID) |
| Inbound client auth | **Per-prefix Entra issuer/audience/jwks** — a dev token cannot authenticate against prod |
| Gate policy (Trivy threshold, base images) | **Shared now, per-prefix later** — policy engine stays a global singleton; config structured so per-prefix overrides can be added without reworking routing |
| Backward compatibility | **Hard cut + chart migration** — remove old `acr.registry`/flat `auth.*`; migrate chart + `values.*.yaml` in the same change. One config schema, one code path. |
| Implementation approach | **A: Tenant registry resolved per-request in the Handler** — one `tenant.Resolver` owns all host→tenant logic; handlers read a resolved `Tenant`; single-environment deploy is a one-entry tenant list |

## Architecture

### New package: `internal/tenant`

The single owner of host→tenant logic. Host parsing (strip `:port`, strip
`base_domain`, take leading label) lives ONLY here.

```go
// Tenant bundles everything that was single-valued before.
type Tenant struct {
    Prefix   string
    Registry string             // e.g. c3devacr.azurecr.io
    Pusher   acr.Pusher         // per-prefix workload identity
    Authn    auth.Authenticator // per-prefix Entra validator (token endpoint)
}

type Resolver interface {
    // ForHost strips the base domain, takes the leading label as prefix,
    // and returns that prefix's Tenant. Unknown prefix -> (nil, ErrUnknownTenant).
    ForHost(host string) (*Tenant, error)
}

var ErrUnknownTenant = errors.New("tenant: unknown registry prefix")
```

- `staticResolver` is built once at startup from config into a
  `map[prefix]*Tenant`. For each tenant it constructs the per-prefix
  `acr.Pusher` and per-prefix `auth.Authenticator`.
- `ForHost` is case-insensitive, strips an optional `:port`, strips the
  configured `base_domain`, and uses the remaining leading label as the prefix.

### `internal/acr` — new constructor

```go
func NewACRPusherWithClientID(registry, clientID string) (Pusher, error)
```

Builds a `WorkloadIdentityCredential` via
`azidentity.NewWorkloadIdentityCredential` with the per-prefix client ID,
instead of `DefaultAzureCredential`. The existing `acrCredAuthenticator` is
unchanged — its AAD→ACR exchange is already keyed by `registry`, so it simply
receives the per-tenant credential.

### `internal/ingress/docker` — Handler holds a `Resolver`

The Handler fields `registry`, `outcome.Pusher`, and `auth` are replaced by a
single `resolver tenant.Resolver`. Each entry point resolves once:

- `route` / `authenticate` / `handleManifest` / `handleUpload` call
  `t, err := h.resolver.ForHost(r.Host)`. On `ErrUnknownTenant` they return
  **404** before any work.
- `t.Registry` replaces `h.registry`.
- `t.Pusher` replaces `h.outcome.Pusher`.
- `t.Authn` replaces the token handler's authenticator.

### `internal/auth` — registry token carries its tenant

The minted registry token gains a `prefix` claim. `/v2/` verification checks the
token's `prefix` matches the resolved host's prefix, so a token issued on the dev
host cannot be replayed against prod. Signing secret stays shared; scope is
per-tenant.

### `internal/app` — `BuildWithBackends` builds the resolver

Loops over `tenants[]`, builds each `Tenant` (per-prefix pusher + authn),
constructs the `staticResolver`, injects it into the Handler. Policy engine,
staging store (blob + Valkey), audit, and scan pool remain shared singletons.

## Config schema (hard cut)

```yaml
acr:
  registry_template: "{prefix}acr.azurecr.io"   # {prefix} substituted from the host's leading label
  base_domain: "c3ci.cloud"                     # stripped from Host; leading label = prefix

tenants:
  - prefix: c3dev
    acr_client_id: "${C3DEV_ACR_CLIENT_ID}"     # outbound ACR push (workload identity)
    auth:                                        # per-prefix inbound auth
      issuer:    "https://login.microsoftonline.com/<dev-tenant>/v2.0"
      audience:  "api://merlin-dev"
      jwks_url:  "https://login.microsoftonline.com/<dev-tenant>/discovery/v2.0/keys"
      tenant_id: "<dev-tenant>"
  - prefix: c3prod
    acr_client_id: "${C3PROD_ACR_CLIENT_ID}"
    auth:
      issuer:    "https://login.microsoftonline.com/<prod-tenant>/v2.0"
      audience:  "api://merlin-prod"
      jwks_url:  "https://login.microsoftonline.com/<prod-tenant>/discovery/v2.0/keys"
      tenant_id: "<prod-tenant>"

auth:
  # Shared registry-token signing + TTL (the short-lived token /v2/ verifies).
  registry_token_secret: ${REGISTRY_TOKEN_SECRET}
  registry_token_ttl: 5m
  service: merlin
```

**Removed:** `acr.registry`, `auth.issuer`, `auth.audience`, `auth.jwks_url`,
`auth.tenant_id` (these move into each tenant; the template derives the registry
host). Shared sections unchanged: `trivy`, `base_image`, `staging`, `audit`,
`server`.

**Validation (fail fast at startup, name the offending prefix):**
- at least one tenant
- unique prefixes
- each tenant: non-empty `acr_client_id` + complete `auth` block (issuer,
  audience, jwks_url, tenant_id)
- `registry_template` contains `{prefix}`
- `base_domain` non-empty

## Data flow (buildx push to `c3prod.c3ci.cloud`)

1. `docker push c3prod.c3ci.cloud/team/app:tag` → `/v2/`, no token →
   `authenticate` resolves tenant (`c3prod`), issues `WWW-Authenticate` with
   realm pointing at `c3prod.c3ci.cloud/token`.
2. `GET /token` (same host) → `TokenHandler` resolves tenant → validates inbound
   credential against **c3prod's** Entra authenticator → mints registry token
   with `prefix: c3prod`.
3. Blob `POST/PATCH/PUT` and manifest `PUT` → `/v2/` verifies token signature
   **and** that token's `prefix` == resolved host's prefix (else 401). Staging
   (blob bytes + Valkey) is shared/global, unchanged.
4. Manifest gate: assemble → policy engine (global) → on pass,
   `t.Pusher.PushManifest` to `c3prodacr.azurecr.io` using c3prod's workload
   identity. Audit records the event (shared ClickHouse), tagged with the target
   as today.

## Error handling

| Condition | Response |
|---|---|
| Unknown prefix / bare base domain (no match) | **404** before auth — docker reports "registry not found" cleanly |
| Token `prefix` mismatch (dev token on prod host) | **401**, re-challenge |
| Malformed Host (no leading label) | **404** via `ErrUnknownTenant` |
| Per-tenant backend build failure at startup (bad client ID, JWKS unreachable) | `BuildWithBackends` fails fast naming the offending prefix; process does not start half-wired |

## Testing

- `internal/tenant`: table-driven `ForHost` — valid prefixes, `:port`
  stripping, unknown prefix, bare base domain, case-insensitivity; fake
  pusher/authn injected (no network).
- `internal/acr`: `NewACRPusherWithClientID` constructs without panicking;
  exchange URL still keyed per registry (extend `push_cred_test.go`).
- `internal/auth`: registry token round-trips the `prefix` claim; verification
  rejects a mismatched prefix.
- `internal/ingress/docker`: existing handler tests use a fake `Resolver`
  returning one tenant (preserves current coverage); add a 2-tenant test
  asserting a dev-host push targets the dev pusher and a cross-prefix token is
  rejected 401.
- `internal/config`: multi-tenant parse + validation (dup prefix, missing client
  ID, template without `{prefix}`, empty tenants).
- Run `go test -race ./...`; maintain 80%+ coverage.

## Chart migration (same change)

- `charts/merlin/values.yaml`: replace `merlin` single-registry fields with
  `acr.registryTemplate`, `acr.baseDomain`, and a `tenants` list. Each tenant's
  `acrClientId` and per-prefix Entra config rendered into the ConfigMap.
- `charts/merlin/templates/configmap.yaml`: render `acr.registry_template`,
  `acr.base_domain`, and the `tenants[]` block; drop `acr.registry` and flat
  `auth.*` env/issuer fields.
- `charts/merlin/templates/ingress.yaml`: support multiple hosts (one per
  prefix, or a wildcard for the shared base domain) routing to the same
  service.
- `charts/merlin/templates/deployment.yaml`: per-prefix `acr_client_id`s are
  config values (federated workload identity), so no new secret wiring; verify
  `azure.workload.identity/use: "true"` still applies.
- Migrate `values.prod.example.yaml`, `values.opsadmin.yaml`,
  `values.smoke.yaml` to the new schema.

## Out of scope (explicit YAGNI)

- Per-prefix gate policy (Trivy threshold, allowed base images) — structured for
  but not implemented now.
- Per-prefix staging/audit isolation — staging store, Valkey, ClickHouse, and
  the scan pool remain shared singletons.
- Per-prefix SP secrets — workload identity only.
- Dynamic/hot-reload of tenants — resolver is built once at startup.
