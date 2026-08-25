# Deploy history and operational findings (opsadmin)

The live deployment is configured by `values.opsadmin.multiacr.yaml`, which is **not tracked**
(see `.gitignore`, alongside `values.opsadmin.yaml`): it carries Entra tenant/client/audience
identifiers for a specific cluster and those do not belong in a public repository. See
`values.opsadmin.multiacr.example.yaml` for its shape.

That file used to carry its own history in comments. The comments are the part worth keeping —
several are load-bearing warnings that cost real incidents to learn — so they live here instead,
with identifiers replaced by placeholders.

## Build the image the way the live image is built

The FIPS runtime base is a build arg, not a default. Omit it and the image silently regresses to
public wolfi:

```
docker buildx build --platform linux/amd64 \
  --build-arg RUNTIME_BASE=<dev-registry>/c3.ai/chainguard-base-fips:latest-<tag> \
  -t <dev-registry>/merlin:<sha> --push .
```

Then `helm upgrade merlin charts/merlin -f values.opsadmin.multiacr.yaml -n c3-opsadmin`.

`image.pullPolicy` is pinned to `Always` on purpose: tags here are git SHAs that get rebuilt and
re-pushed during iteration, so `IfNotPresent` would silently run a stale cached layer on a node
that already has the tag.

## Rollback floor — do NOT roll back past 23593c2

`23593c2` superseded `29992b1`, which was rolled back after seven minutes: its memory-bounded scan
could not exec grype (bare name, and `syscall.Exec` does not search PATH) and the gate is
fail-closed, so **every** push got a 500. That image also could not claim a promotion — the
deployed Valkey runs `cluster_enabled:1` and the claim script spanned hash slots. Do not roll back
to `29992b1` or any earlier async-promote build.

## Fixes, in the order they landed

- **`d982de6`** — the largest failure class on the gate (160 rows/24h). The promotion worker's
  recovery sweep ran with `RecoverAfter` unset (`== 0`), and `Recover(ctx, 0)` puts its cutoff at
  *now*, so every 60s sweep on every replica requeued every LIVE claim. The `BlobNotFound` was
  self-inflicted: the first duplicate to finish pushed and ran `Cleanup`, deleting the staged blobs
  the other duplicates were still reading. Also made a missing staged blob terminal, so it is no
  longer retried 3x into three contradictory audit rows.
- **`52d1751`** — the other half of the async-promote fallout, found by pushing a fixture through
  `d982de6`. A buildx index PUT lands ~70ms after the gate's 201, before the queued promotion has
  reached ACR, so ACR rejects the index (`MANIFEST_BLOB_UNKNOWN`), the client's whole push fails
  400, and the gated image sits in ACR **untagged**. The index forward now waits (bounded 90s) and
  the failure says a REFERENCE is missing. This class is invisible in `gate_decisions` — an index
  forward writes no audit row — so watch the logs for
  `forward index -> … succeeded after waiting N attempt(s) for promotion`.
- **`46f0ce5`** — stopped the gate killing its own in-flight scans. The scan context was derived
  from the *request* context, so a client giving up at its hardcoded ~30s response-header ceiling
  canceled it and `exec.CommandContext` SIGKILLed grype mid-scan → `signal: killed` with empty
  stderr → fail-closed `infra_error`. 72 such rows, median 31.1s, read as memory pressure for weeks
  because an OOM kill looks identical (zero `OOMKilled` events, zero restarts — it was never
  memory). `gate_timeout` (5m) was never the trigger. Once a slot is held and grype is running, the
  scan and the publication run on a context detached from the request, still bounded by
  `gate_timeout`. The trade: an abandoned push holds its slot until the scan finishes instead of
  dying at 30s — still cheaper than the status quo, where the client's retry started a second full
  scan of the same image.
- **`e65a3ad`** — refactor only (16 commits, no behaviour change intended), but the first roll where
  wiring moved: `app.Run` owns startup, the docker handler is built from one validated
  `HandlerConfig` instead of 11 setters, metrics register per-collector, and `bootstrapSchema` kept
  only the part that needs a ClickHouse. If a roll like this misbehaves, suspect wiring rather than
  logic: `internal/app/components.go` and `internal/ingress/docker/handler.go` are where
  construction now happens.

## Reliability step 2: closed at 0.7%

Measured across the whole `46f0ce5` window: **852 pushes, 6 `infra_error` (0.7%)**, against a
**20.7%** pre-change baseline, including a 226-push peak hour (above the 197/hour the plan was
waiting for). The per-row `error_detail` labels are what settled the diagnosis, which the counts
alone never could:

- **Zero bare `signal: killed`.** That class was 85% of the baseline (77 rows). It was client
  cancellation, not memory, and detaching the scan context removed it entirely.
- **1** honest `scan exceeded the 5m0s gate budget`, at 300097ms.
- **5** genuine grype OOMs — and all five are the *same image tag*
  (`c3.ai/opensearch-dashboards-fips:3.7.0-r20-<build>`), retried 5x within ten minutes. Its Go
  runtime reports 2.69–2.89 GB in use against the 2Gi `memoryLimit`, so the `RLIMIT_AS` backstop
  turned what used to be an anonymous kernel kill into a diagnosable allocation failure. The same
  repo has 21 clean passes.

So the residual 0.7% is one pathological tag, not a systemic shortfall.

**Open trade, deliberately not taken:** raising `memoryLimit` does not fit the budget. At 3Gi ×
`scanPoolSize: 2` plus the ~5.4Gi upload worst case, the total exceeds the 10Gi container limit, so
it needs `resources.limits.memory` raised or `scanPoolSize` dropped to 1. That is a throughput
decision, not a refactor detail.

## Interpreting `error_detail` on a kill

A kill is no longer the client's doing, so the rows say which:

| `error_detail` | Meaning |
| --- | --- |
| `scan abandoned: client disconnected while it ran (…)` | Impatient client. Expected. |
| `scan exceeded the 5m0s gate budget` | Merlin's own deadline. |
| `runtime: out of memory: cannot allocate …` | grype exceeded its per-scan budget. Diagnosable. |
| a **bare** `signal: killed`, no prefix | The real OOM case, and the one worth paging on. |

## Memory budget arithmetic

Merlin buffers whole blobs in memory during staging (`WriteChunk`/`CompleteBlob` `io.ReadAll`), and
staging re-reads the accumulated upload on every write, so resident cost is ~3x the body per
in-flight upload. Budget against `resources.limits.memory` (10Gi):

```
uploads: maxUploadBytes 2Gi x ~3 x uploadConcurrency 2  ~= 5.4Gi
scans:   memoryLimit 2Gi x scanPoolSize 2               ~= 4.0Gi
total                                                   ~= 9.4Gi < 10Gi
```

Both worst cases coinciding leaves little for merlin itself, so raising either factor needs the
limit raised with it.

- `maxUploadBytes: 2Gi` was **measured, not guessed**: the largest layer across all 36 repos in the
  tenant registry is 0.899 GiB, so 2 GiB leaves >2x headroom. The former 15 GiB was far above any
  real layer and, unbounded, let concurrent pushes OOMKill the pod (both replicas, exit 137).
  Do **not** lower it to the 512Mi chart default, which is sized for the chart's 2Gi limit and
  would reject the 0.899 GiB layer with a 413.
- `scanPoolSize` was lowered 4 → 2: 4 × 2Gi does not fit alongside the upload budget. At the
  observed push rate, scan concurrency was never the throughput constraint; scan memory was.
- `grype.memoryLimit` is applied as `GOMEMLIMIT` on the grype child with a derived `RLIMIT_AS`
  backstop (see `internal/limitexec`). `GOMEMLIMIT` is a *soft* ceiling: exceeding the budget makes
  grype GC harder and scan slower rather than fail, which is the right failure mode for a
  fail-closed gate. Before it was set, grype was the only unbounded memory consumer in the pod —
  279 kernel kills in three weeks, ~14/day — and the killer does not have to pick grype, so a scan
  could take the merlin parent with it and fail every concurrent push.

## ServiceMonitor: verified, and not by the Prometheus you would expect

`metrics.serviceMonitor.labels: {}` is correct — no release label is needed — but the reason
matters:

- The namespace-local `opscenter-kube-prometheus-prometheus` is scaled to **zero** (sts 0/0, Service
  has no endpoints). Its selectors are irrelevant; it consumes nothing. Do not "fix" scraping by
  adding labels for that CR.
- A Prometheus in *another* namespace is what actually scrapes us. Both its
  `serviceMonitorSelector` and `serviceMonitorNamespaceSelector` are empty **maps**, and in the
  Prometheus Operator an empty map means ALL — all ServiceMonitors, in all namespaces. Only an
  **absent** `namespaceSelector` restricts to the CR's own namespace. Easy to get backwards.

Confirmed by asking the running Prometheus, which is the only check that proves anything — the
object existing proves nothing:

```
kubectl get --raw "/api/v1/namespaces/<ns>/pods/prometheus-app-prometheus-0:9090/proxy/api/v1/targets?state=active" \
  | grep -o '"job":"merlin"' | head
```

Both merlin pods came back `health=up` with 21 metric families. Its `scrapeInterval` is 60s, so
`endpoints.interval` is a floor, not a promise.

Until this landed, `/metrics` was served on :9090 and scraped by nobody: every counter and
histogram lived in the pod's memory and was lost on each restart, which is why the
OOMKill/promotion-failure history had to be reconstructed from audit rows.

## Things that are off, and what turning them on costs

- **Alerter.** Off because it needs a credential this repo cannot create: `externalSecrets` is
  disabled, so the webhook must be added by hand to the pre-existing `merlin-secrets` Secret, and a
  pod that renders `${SLACK_WEBHOOK_URL}` without the key fails closed at startup. Patch the secret
  *first*, then enable `merlin.alerts`. The defaults (15m interval, 1h recent vs 168h baseline, 6h
  cooldown) fit this cluster: `audit.retention_days` is 30, so the 7-day baseline is fully retained.
- **`grype.enforce: false`** (set 2026-08-11, temporary). Findings at/above `severityThreshold` are
  still scanned, written to the audit store and shown on `GET /reports/<ref>`; the push summary says
  "published, gate not enforcing" and the pod logs a WARNING at every startup. Nothing is rejected —
  an image with Critical CVEs reaches ACR. Revert by deleting the key (the Go default is
  `enforce: true`).
- **`serviceAccount.create: false`** — reuses an existing SA managed by another release. Do NOT
  recreate it.
- **ClickHouse `dataSize: 20Gi`** matches the live PVC, which was created from the chart default.
  PersistentVolumeClaims cannot shrink, so a smaller value here is an invalid downsize on upgrade.

## Verifying a deploy

"7/7 Running" does not catch a mis-wire. The `e65a3ad` roll was verified by pushing a fixture
through the live gate end to end: token → 200, blob PUTs → 201, manifest PUT → 201 in 47.3s,
`passed=true`, image-age gate read `created` (15d, known), and the promotion was claimed by a
**different** replica than the one that assembled it, rebuilt the layout locally, reached ACR with
`merlin_acr_push_total{result="ok"}`, and the queue returned to 0.

The audit bootstrap path is proven by the pods booting at all: `execGroups` runs on every start,
which is precisely why it is 0% covered hermetically.

Push recipe (the gate host is per-tenant `<prefix>.<baseDomain>`, not the dashboard host):

```
az account get-access-token --resource api://<audience-app-id> --query accessToken -o tsv \
  | docker login <prefix>.<baseDomain> -u 00000000-0000-0000-0000-000000000000 --password-stdin
docker push <prefix>.<baseDomain>/e2e/gatecheck:<tag>
```

Audit queries: the table is `merlin.gate_decisions` (not `push_decisions`), ClickHouse user
`merlin`, password from secret key `clickhouse-password` (the env var is `CLICKHOUSE_PASSWORD`, but
that is not the secret key). Columns are `image_repo`/`image_tag`; there is no `image_ref`. Note
that the label `app.kubernetes.io/name=merlin` **also** matches the ClickHouse pod, so target gate
pods by name or you will exec into ClickHouse.

---

## Appendix: deploy records recovered from pruned commits

Seven commits touched *only* the untracked values file, so removing that file from history
pruned them entirely. They contained no code, but their messages were the deploy log. They are
reproduced here so the record survives, oldest first.

> **One of these is wrong and was corrected later.** `368f934` concluded that the
> `azplatdevops` Prometheus "will not scrape merlin" and that the namespace-local
> `opscenter-kube-prometheus-prometheus` was the scraper. The opposite is true, as verified
> afterwards by querying the running Prometheus: `opscenter` is scaled to **zero** and consumes
> nothing, while the `azplatdevops` CR has empty **maps** for both selectors, which the operator
> reads as *all* ServiceMonitors in *all* namespaces. See the ServiceMonitor section above. It is
> kept here unedited because the mistake — reading an empty map as "own namespace only" — is the
> easy one to repeat.

### `0ce1e90` — deploy: merlin 91be825 (observability metrics fix, rev 7)

No body. This is the commit that first introduced the values file, and with it the Entra
identifiers.

### `7e780e1` — deploy: merlin d615c54 (ACR refresh-token cache fix, rev 9)

Ship `a15447d` — cache the ACR refresh token by its own expiry rather than the AAD token's — to
the c3-opsadmin release. Fixes the intermittent 502s on long-running pods. helm rev 9, both
replicas READY on `d615c54`.

### `5713bd2` — deploy(opsadmin): bound upload memory, pin image, fix drifted values

`maxUploadBytes` 15 GiB → 2 GiB and `uploadConcurrency` 2. Sized from measurement, not guesswork:
the largest layer across all 36 repos in the tenant registry is 0.899 GiB, so 2 GiB keeps >2x
headroom while the 2 × ~3 × 0.9 GiB worst case (~5.4Gi) fits under the 10Gi limit. The old 15 GiB
with no concurrency bound is what OOMKilled both replicas (exit 137, 2026-08-06). Not lowered to
the 512Mi chart default, which is sized for the chart's 2Gi limit and would 413 the 0.899 GiB
layer.

Two pre-existing drifts caught by `helm diff` against the live release:

- `pullPolicy` was unset, so the chart default `IfNotPresent` would have replaced the live
  `Always`. Tags are git SHAs that get rebuilt during iteration, so `IfNotPresent` can run a stale
  cached layer.
- `clickhouse.storage.dataSize` said 5Gi while the live PVC is 20Gi. PVCs cannot shrink, so an
  upgrade would request an invalid downsize.

Image tag → `05ba6ba` (staging leak fixes + bounded upload memory).

### `c8ec505` — deploy(opsadmin): merlin 29992b1 (async promotion + non-enforcing grype)

Image tag `05ba6ba` → `29992b1`. Carries two changes: async ACR promotion off the manifest-PUT
path, plus the multi-replica Localize fix and the pending-promotion bound (`48ab72d`); and
`grype.enforce=false` with `grype.memory_limit=2Gi` (`29992b1`).

`helm diff` against live rev 18 was exactly the image tag plus `enforce: false`,
`memory_limit: "2Gi"` and `scan_pool_size` 4 → 2. No config drift this time.

Built with `--build-arg RUNTIME_BASE=<dev-registry>/merlin:05ba6ba` rather than the default
`cgr.dev/chainguard/wolfi-base`: the cgr.dev credential helper deadlocks under buildkit (headless
prompt with no readable stdout) and the local token cache is stale. `05ba6ba` **is** that same
wolfi base plus the two binaries this build overwrites, so the content is equivalent — verified on
the pushed image: `/etc/os-release` still reports `ID=chainguard`, so the base-image policy is
unaffected.

### `2d14eb2` — deploy(opsadmin): roll forward to 23593c2 after rev 19 rollback

Rev 19 (`29992b1`) was rolled back after seven minutes. It carried two independent faults that
only surface against live infrastructure:

- The memory-bounded scan could not exec grype. The trampoline reaches the child through
  `syscall.Exec`, which does no PATH lookup, and the caller passes a bare name. Because the gate is
  fail-closed, a scan that cannot run is a rejected push: **140 consecutive 500s**, zero successful
  pushes from 23:13 to 23:19.
- `Claim` spanned Redis hash slots. The deployed Valkey runs `cluster_enabled:1`, which rejects a
  multi-key EVAL whose keys hash differently, so no replica could drain the promote queue. With the
  201 now preceding promotion, that silently reproduced "approved but never published".

Both fixed in `23593c2` and verified end to end against the live cluster with the image that
OOM-killed grype 11 times that day: scan completed in 61s under the 2 GiB bound, promotion was
claimed across replicas, and the byte-identical digest landed in ACR.

### `368f934` — deploy(opsadmin): roll to 767a66d, confirm the Prometheus selector accepts us

*(Contains the reversed conclusion flagged above.)*

Pins the image to `767a66d` (built amd64 on the same `chainguard-base-fips` base as the running
`23593c2` — verified by comparing `/etc/os-release` and the fips apk set inside both, since the
Dockerfile's default `RUNTIME_BASE` is public wolfi and would have silently dropped FIPS).

Observability only. The ACR-push counter moves to the real push sites, request and scanner-DB-age
metrics appear, and the ServiceMonitor is created. The Slack alerter ships but stays OFF: no
webhook is configured here, and the webhook is the switch. No gate-path behaviour changes.

Also resolves the UNVERIFIED note left on `metrics.serviceMonitor.labels`. Checked live:
`opscenter-kube-prometheus-prometheus` has `serviceMonitorSelector={}` and a `namespaceSelector`
matching c3-opsadmin, so `{}` is right and no release label is needed. The other CR,
`app-prometheus`, has an empty `namespaceSelector`, which the operator reads as its own namespace
only — it will not scrape merlin. **← this last sentence is the error; see above.**

Recorded the exact build command in the values comment. The FIPS base is the kind of detail that is
invisible in a diff and expensive to discover from a running pod.

### `b93ee88` — deploy(opsadmin): pin 52d1751 (promote recovery + terminal 404 + index wait)

Rolled to c3-opsadmin and verified live: a fixture push that failed 400 with
`MANIFEST_BLOB_UNKNOWN` on `d982de6` now succeeds, the index forward absorbing the race in 6
attempts over 3.07s, with the tag landing on the index digest in ACR. The gate decision is a single
`passed` row where this push shape previously wrote one pass plus six contradictory `infra_error`
rows.
