# Infra-error observability for the Merlin push gate

**Date:** 2026-07-10
**Status:** Design approved, pending spec review
**Scope:** (b) attribution + full request visibility

## Motivation

On PR 2431, a push to `c3devops.azurecr.io` failed with a 502. Investigation
(live `kubectl` + pod logs) established the root cause was **not** a crash or
OOM:

```
manifest c3devops.azurecr.io/c3aiops:pr-2431-... gate outcome infra error:
  acr push: POST https://c3devops.azurecr.io/oauth2/token: unexpected status code 401 Unauthorized
v2 PUT /v2/c3aiops/manifests/pr-2431-... -> 502 (26B, 1m26.874s)
```

The gate scan **passed**, then the ACR push failed on the second leg of ACR
OAuth2 (`/oauth2/token`, refresh-token → scoped access token) with a **401
Unauthorized** — an authorization problem on the tenant's workload identity, not
a Merlin fault. Merlin correctly returned its application-level 502
("passed but ACR push failed", `internal/ingress/docker/outcome.go`).

The failure recurred on PR 2432/2424/2433 (same 401), so it is persistent, not
transient.

**Root cause (confirmed 2026-07-11 via live Azure + kubectl):** the Merlin pod
runs under the shared `c3aiops` ServiceAccount (owned by the `c3aiops` Helm
release, ~90 pods), annotated with managed identity `4eee465b`
(`azplatdevops-c3-mi-01`), which had **no** AcrPush on `c3devops`. Merlin's config
names a *different* identity `7bb01327` (`azplatinfosec5-c3-mi-01`,
`acr_client_id` in `values.opsadmin.multiacr.yaml:61`) that *does* hold AcrPush.
Both MIs are federated to the same SA subject
`system:serviceaccount:c3-opsadmin:c3aiops`, so the identity that actually
reached ACR (`4eee465b`) lacked push rights → 401 on the scoped-token leg. This
is an **identity mismatch**, not a missing role on the configured identity.
Interim fix: granted AcrPush to `4eee465b` on `c3devops` (broad blast radius —
shared identity). Least-privilege fix would give Merlin its own SA annotated with
the dedicated push identity.

### The observability gap this fixes

The failure *was* technically recorded, but was not actionable on the dashboard:

1. `merlin_acr_push_total{result="error"}` incremented, but the counter has only
   a `result` label — no way to see **which registry** failed or **why**
   (auth vs network vs timeout).
2. The audit store recorded the decision with `passed = false` and empty
   `failed_policies` — **indistinguishable from a genuine policy rejection** on
   the dashboard. The 502 was silently miscounted as a normal reject.
3. The 502 itself exists only in the text access log — there is no
   request-level HTTP-status metric.

### Explicitly out of scope

- **Crash / panic capture** (scope c): no `recover()` middleware is added. A
  genuine panic still crashes the process without being counted. Chosen scope is
  (b), not (c). OOMKills are a pod-level event surfaced by Kubernetes
  (`kube_pod_container_status_last_terminated_reason`), not Merlin's own metrics,
  and belong to a k8s alert rather than this code change.
- **Fixing the 401 itself** — that is an Azure RBAC / workload-identity change
  (grant/repair `AcrPush` on `c3devops.azurecr.io`), tracked separately.
- **Chart resource-default drift** — `charts/merlin/values.yaml` defaults to 2Gi
  memory while the live deploy runs 10Gi. The 2Gi default is a latent OOM risk
  for the assemble/scan path on large images, but it is a deploy-config concern,
  not observability. Captured as a **follow-up**, not implemented here.

## Architecture

Three independent, small changes, each in the package that owns the data. No new
packages; the only new interfaces are local to the `docker` ingress package
(mirroring the existing `MetricsObserver` pattern so `handler.go`/`outcome.go`
need not import `observability` directly).

| # | Change | Files |
|---|--------|-------|
| A | Classify ACR push failure into a coarse class; add `registry` label to the ACR counter | `internal/acr/classify.go` (new), `internal/observability/metrics.go`, `internal/ingress/docker/outcome.go` |
| B | New `merlin_requests_total{method,route,status}` counter | `internal/observability/metrics.go`, `internal/ingress/docker/handler.go` |
| C | `InfraError` audit column so an infra 502/500 is not counted as a policy reject | `internal/audit/audit.go`, `internal/audit/schema.sql`, `internal/audit/clickhouse.go`, `internal/audit/dashboard_queries.go`, `internal/ingress/docker/outcome.go` |

## Change A — ACR push failure classification

### `internal/acr/classify.go` (new)

Bounded, low-cardinality classification. Uses `errors.As`, no string matching.

```go
type PushErrorClass string

const (
    PushErrAuth     PushErrorClass = "auth"      // HTTP 401, 403
    PushErrNotFound PushErrorClass = "not_found" // HTTP 404
    PushErrTimeout  PushErrorClass = "timeout"   // context deadline, 408, 429, 504
    PushErrNetwork  PushErrorClass = "network"   // dial/conn errors, no HTTP status
    PushErrOther    PushErrorClass = "other"     // everything else
)

func ClassifyPushError(err error) PushErrorClass
```

Classification order:
1. `context.DeadlineExceeded` / `context.Canceled` → `timeout`
2. `*transport.Error` (go-containerregistry) by `StatusCode`:
   - 401, 403 → `auth`
   - 404 → `not_found`
   - 408, 429, 504 → `timeout` (back-off/retry signals grouped with timeout)
   - else → `other`
3. `net.Error` / `*url.Error` → `network`
4. default → `other`

For PR 2431's 401 this returns `auth`.

### `internal/observability/metrics.go`

Extend the existing `acrPush` collector from one label to two, and change the
observe signature:

```go
acrPush: prometheus.NewCounterVec(prometheus.CounterOpts{
    Name: "merlin_acr_push_total",
    Help: "ACR push attempts by registry and result.",
}, []string{"registry", "result"}),

// result is "ok" on success, else the coarse class from ClassifyPushError.
func (m *Metrics) ObserveACRPush(registry, result string)
```

Adding the `registry` label is backward-compatible: existing panels that query
`merlin_acr_push_total` without a `registry` selector still work (Prometheus sums
across labels).

### `internal/ingress/docker/outcome.go`

The local `MetricsObserver` interface method becomes
`ObserveACRPush(registry, result string)`. `Apply` derives `registry` from the
host portion of `req.Target` (e.g. `c3devops.azurecr.io`), so no new parameter is
threaded through:

```go
if err := pusher.Push(ctx, req.Image.OCIPath, req.Target); err != nil {
    if o.Metrics != nil {
        o.Metrics.ObserveACRPush(registry, string(acr.ClassifyPushError(err)))
    }
    o.recordDecision(ctx, pushID, req, res, false, true /*infraError*/, durMS)
    return Decision{StatusCode: 502, Summary: "passed but ACR push failed", ...},
        fmt.Errorf("acr push: %w", err)
}
if o.Metrics != nil {
    o.Metrics.ObserveACRPush(registry, "ok")
}
```

**Cardinality:** `registry` (one per tenant, a handful) × `result` (6) — safe.

## Change B — request-level counter

### `internal/observability/metrics.go`

```go
requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
    Name: "merlin_requests_total",
    Help: "Docker V2 requests by method, route class, and response status.",
}, []string{"method", "route", "status"}),

func (m *Metrics) ObserveRequest(method, route, status string)
```

### `internal/ingress/docker/handler.go`

`ServeHTTP` already wraps every response in `statusWriter`. Increment once after
the mux returns:

```go
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
    start := time.Now()
    h.mux.ServeHTTP(sw, r)
    if h.metrics != nil {
        h.metrics.ObserveRequest(r.Method, routeClass(r.URL.Path), strconv.Itoa(sw.status))
    }
    log.Printf("v2 %s %s%s -> %d (%dB, %s)", ...)
}
```

`routeClass` is the cardinality guard — raw paths (with unique tags/digests)
never become labels, only the bounded class does:

```go
func routeClass(path string) string {
    switch {
    case path == "/v2/" || path == "/v2":            return "base"
    case path == "/token":                           return "token"
    case strings.HasPrefix(path, "/reports/"):       return "report"
    case strings.Contains(path, "/blobs/uploads/"):  return "blob_upload"
    case strings.Contains(path, "/blobs/"):          return "blob"
    case strings.Contains(path, "/manifests/"):      return "manifest"
    case strings.HasPrefix(path, "/v2/"):            return "v2_other"
    default:                                          return "other"
    }
}
```

`/token` and `/reports/` are served by the same mux and are counted too (full
request visibility, matches scope b).

**Wiring:** a new local interface keeps `handler.go` free of an `observability`
import, consistent with the `MetricsObserver` pattern:

```go
// RequestObserver receives per-request telemetry. observability.Metrics satisfies it.
type RequestObserver interface {
    ObserveRequest(method, route, status string)
}
```

Set via a nil-safe `SetRequestObserver(RequestObserver)` option-setter on
`Handler` (mirrors `SetPool`/`SetGateTimeout`/`SetScratchBaseDir`).

**Cardinality:** method (~3) × route (~8) × status (~10) — bounded, safe.

## Change C — `InfraError` audit column

### `internal/audit/audit.go`

Add to `Decision`:

```go
InfraError bool // true when the decision is an infra failure (500/502), not a policy reject
```

### `internal/audit/schema.sql`

In the `CREATE TABLE gate_decisions`:

```sql
infra_error Bool DEFAULT 0,
```

Plus an idempotent online migration for existing deployments (matching the
existing age-column pattern):

```sql
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS infra_error Bool DEFAULT 0;
```

### `internal/audit/clickhouse.go`

Add `infra_error` to the `WriteDecision` INSERT column list and value bindings.

### `internal/ingress/docker/outcome.go`

`recordDecision` gains an `infraError bool` parameter. Pass `true` on the
scan-could-not-complete (500) and ACR-push-failed (502) paths, `false` on the
pass (201) and policy-reject (400) paths.

### `internal/audit/dashboard_queries.go`

`DecisionStatsSince` — separate infra failures from policy rejections. Keep
`countIf` aliases distinct from column names (per the ClickHouse 26.x
`ILLEGAL_AGGREGATION` trap documented in commit `a925812`):

```sql
SELECT
  count() AS total,
  countIf(passed) AS n_passed,
  countIf(NOT passed AND NOT infra_error) AS n_rejected,
  countIf(infra_error) AS n_infra_error,
  quantile(0.5)(duration_ms) AS p50,
  quantile(0.95)(duration_ms) AS p95,
  quantile(0.99)(duration_ms) AS p99
FROM gate_decisions WHERE ts >= ?
```

`DecisionStats` gains an `InfraError` count field; the reject-reasons subquery
also filters `AND NOT infra_error` so an infra 502 (empty `reasons`) does not
pollute the top-reject-reasons panel.

## Testing

Following the repo's table-driven Go style, run with `-race`:

- **A:** `classify_test.go` — table of `(error, want PushErrorClass)`: a
  `*transport.Error{StatusCode:401}` → `auth`, 404 → `not_found`, 429 → `timeout`,
  a `net`/dial error → `network`, `context.DeadlineExceeded` → `timeout`, a bare
  error → `other`. Extend `metrics_test.go` for the two-label `ObserveACRPush`.
- **B:** `handler_test.go` — a fake `RequestObserver` capturing calls; assert
  `routeClass` mapping for representative paths and that `ServeHTTP` records
  `(method, route, status)` once per request. Unit-test `routeClass` directly.
- **C:** extend `clickhouse_integration_test.go` — write a decision with
  `InfraError=true`, assert `DecisionStatsSince` reports it under `n_infra_error`
  and **not** under `n_rejected`; a policy reject lands in `n_rejected`.
- Target ≥ 80% coverage on new code.

## Follow-ups (not in this work)

1. **Credential-cache bug (ACTUAL root cause of the 401 — fixed in commit
   a15447d):** `internal/acr/credential.go` cached the ACR refresh token but keyed
   its expiry off the AAD access token's `ExpiresOn`. The two tokens have
   independent lifetimes (AAD ~24h, ACR refresh ~3h), so a stale refresh token was
   reused for hours and ACR's `/oauth2/token` leg rejected it with 401 → push 502.
   Fixed by caching to the refresh token's own `exp` claim. Both earlier theories
   (missing RBAC; dual-MI identity mismatch) were WRONG — the identity/roles were
   fine. **Deploy a15447d to prod** (running `merlin:a925812`) to resolve CI, and
   **revoke** the inert `4eee465b` AcrPush grant added under the wrong hypothesis.
2. **Chart resource default:** reconcile `charts/merlin/values.yaml` 2Gi default
   with the live 10Gi to avoid a large-image OOM on a fresh tenant deploy.
3. **k8s crash alert:** alert on
   `kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}` for the
   crash-visibility gap (scope c), since OOM/panic are pod-level, not app-metric,
   events.
