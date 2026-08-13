# Gate reliability: fixing a 50% infra-error rate

**Status:** proposed, 2026-08-13
**Trigger:** the observability shipped in `767a66d` (§0 step 4/5 of
[2026-08-11-llm-observability-agent.md](2026-08-11-llm-observability-agent.md)) made the
gate's real failure rate visible for the first time. It is ~50%.

## The measurement

From `gate_decisions` on the live c3-opsadmin cluster, 2026-08-13:

| Window | Decisions | infra_error | Rate |
|---|---|---|---|
| 1h | 72 | 40 | **55.6%** |
| 168h | 1103 | 545 | **49.4%** |

Hourly for 12h: 54, 52, 42, 47, 43, 57% — **chronic, not a spike.** `grype.enforce` is
`false`, so none of this is CVE gating. Every one of these is infrastructure.

Three failure classes, all of them infra:

| Class | Count/24h | duration min/med/max | First seen |
|---|---|---|---|
| `acr promotion abandoned after 3 attempts: … BlobNotFound` | 160 | 0s (async worker) | 2026-08-12 01:00 |
| `grype … run grype: signal: killed` | 72 | 0.5 / **31.1** / 118.5s | 2026-08-11 17:57 |
| `grype … exit status 2: runtime: out of memory` | 13 | 95.8 / 101.4 / 160.3s | 2026-08-12 01:09 |

Both first-seen timestamps line up with a deploy: `signal: killed` with the
memory-bounded scan (`23593c2`, 2026-08-11 17:57), and the promotion failures with async
promote (2026-08-12 01:00). Neither is a coincidence.

## §0 Sequencing

Ordered by user-visible harm, not by effort. Each step is independently shippable and
independently verifiable; none depends on a later one.

| # | Step | Effort | Why this order |
|---|---|---|---|
| 1 | **Stop losing published images** — promotion `BlobNotFound` | ~1–2 days | Silent data loss: the gate says pass, the image never reaches ACR. The only class where the client is told everything is fine |
| 2 | **Stop killing in-flight scans** — decouple scan ctx from `r.Context()` | ~2h | ~10 lines. Stops throwing away 30–120s of completed scan work per abandoned push |
| 3 | **Make scans fast again** — retune the memory bound | ~half day + a soak | The root cause upstream of step 2. Needs a capacity decision, so it is not a pure code change |
| 4 | **Reuse a completed decision on retry** | ~1 day | What converts steps 2+3 into a *client-visible* fix rather than only less wasted work |
| 5 | **Un-blind the alerter** — floor-OR-factor, ref normalization, kill attribution | ~half day | Cheap, but worthless before 1–4: it would just page about a known 50% |

**What this plan is not:** no new scanner, no change to the fail-closed contract, no
incident lifecycle, no move to a queue/202 push model (see step 4's rejected option).

---

## 1. Promotion abandons published images on `BlobNotFound`

**Evidence.** 160 rows in 24h, the single largest failure class:

```
acr promotion abandoned after 3 attempts: rebuild oci layout for
c3devops.azurecr.io/c3.ai/dcgm-exporter-fips:4.6.0.4.8.3-r1-202607310210:
re-assemble …: get blob sha256:da82c86a…: RESPONSE 404: BlobNotFound
```

**Root cause (hypothesis, needs one confirming query).** The async worker
(`internal/promote/worker.go`, `defaultMaxAttempts = 3`) re-assembles the OCI layout from
staged blobs at promotion time, but the staged blob is already gone from
`merlin-staging`. The prime suspect is cleanup running against blobs the queued job still
needs — `manifest.go:239` calls `h.store.Cleanup(context.WithoutCancel(ctx), …)` on the
synchronous path, and the job's own comment warns that "every field the worker's Cleanup
needs must be carried on the Job … Omitting any of them leaks the staged blobs". This is
the inverse: not a leak, a premature delete. Timing corroborates — first occurrence is
53 minutes after async promote went live.

**Confirm first (do not fix blind).** For one failing digest, establish the order of
events: was the blob deleted by the sync path's `Cleanup` before the worker claimed the
job, or did the upload never land? Query `tag_aliases` + the audit row for the same
`push_id`, and list the staging container for a sibling digest of the same push.

**Change.** Whichever the confirmation shows:
- If premature cleanup: the sync path must not release blob ref-counts for a push whose
  promotion is still queued. Ref-count release becomes the *worker's* responsibility on
  terminal success/abandon, and the sync path releases only when `h.promoter == nil`.
- If the blob never landed: the enqueue must happen after durable blob commit, not before.

**Also, regardless of cause:** a job that exhausts `MaxAttempts` on a *missing input*
should not be retried 3× (it cannot succeed — 404 is terminal, unlike a network error),
and it must not report `passed` upstream. Distinguish terminal from retryable in the
worker's error classification.

**Verify.** `SELECT count() FROM gate_decisions WHERE infra_error AND error_detail LIKE
'%BlobNotFound%' AND ts > now()-INTERVAL 1 HOUR` → 0, sustained over a soak that includes
the 17:00–18:00 traffic peak (169 pushes/h observed). Cross-check a sample of `passed`
pushes actually exist in ACR via `az acr repository show-tags`.

---

## 2. An abandoned client SIGKILLs the scan

**Evidence.** Median duration of the `signal: killed` class is **31.1s**, sitting exactly
on the docker/buildx hardcoded ~30s response-header ceiling. Zero `OOMKilled` container
events, zero pod restarts across all 10 pods.

**Root cause — confirmed, and it is not OOM.** `internal/ingress/docker/manifest.go:144`
takes `ctx := r.Context()`; line 306 derives the scan context from it
(`gctx, cancelScan := context.WithTimeout(ctx, timeout)`); the grype child runs under it
via `exec.CommandContext` (`internal/policies/grype/exec_runner.go:58`). Go sends
**SIGKILL** on context cancel, and `.Output()` surfaces that as `signal: killed` with
empty stderr — matching the audit rows exactly. So: client gives up at 30s → request
context cancels → grype is killed mid-scan → fail-closed → `infra_error`.

`gate_timeout` is `5m` and is **not** the trigger; these die at ~31s.

**The trap this creates for anyone reading the logs.** `signal: killed` looks exactly
like an OOM kill, and the memory bound landed the same day the class appeared. It is
neither the cgroup killer nor RLIMIT_AS (that produces `exit status 2` /
`fatal error: out of memory`, class 3 — a genuinely different row).

**Change.** The slot-wait path already handles client disappearance deliberately
(`case aerr != nil:` → "Client disconnected while queued: nothing to scan, no one to
answer" → `return`). The scan path should make the opposite choice: once a scan slot is
held and grype has started, finish the scan on a context detached from the request
(`context.WithoutCancel(ctx)` + `WithTimeout(gate_timeout)`), so the decision is recorded
and the work is not discarded. The client still gets nothing — it already left — but the
push stops costing 30–120s of pool time for zero result, and step 4 makes the retry cheap.

**Distinguish the cause in the audit row.** A scan killed by client-disconnect and a scan
killed by the kernel must not share one `error_detail`, or step 5's detector cannot tell
memory pressure from client impatience. Record which: check `gctx.Err()`/`ctx.Err()` on
failure and label it (`scan abandoned: client disconnected after …` vs the raw signal).

**Verify.** After the change, `signal: killed` rows drop to ~0 and are replaced by either
a clean decision or an explicitly labelled client-abandon row. Scan pool utilisation
(`observeQueueWait`) should improve at peak.

---

## 3. The memory bound is what made scans slow enough to be killed

**Evidence.**

```
exit status 2: runtime: out of memory: cannot allocate 536870912-byte block
(2709585920 in use)  →  fatal error: out of memory
```

A live heap of **2.71 GB** against `memory_limit: 2Gi`, and durations of 95–160s for this
class versus 24–56s averages elsewhere.

**Root cause.** Two bounds from `grype.memoryLimit: 2Gi` (`internal/limitexec`):
- `GOMEMLIMIT=2Gi` is **soft**. An image needing a ~2.7 GB heap is not stopped by it; the
  runtime just GCs harder and harder. That is the documented intent ("trades CPU for
  staying under budget") — but the CPU it trades is wall-clock the 30s client ceiling does
  not have. This is the upstream cause of step 2's kills.
- `RLIMIT_AS = 2 × budget = 4 GiB` is hard. `addressSpaceFactor = 2` is too tight: the
  package's own comment notes a Go runtime's virtual reservation exceeds its live heap "on
  the order of a gigabyte", and at a 2.7 GB heap the virtual footprint clears 4 GiB. Hence
  13 outright deaths.

**Change — and it costs memory, so it is a capacity decision, not just a constant.**
Raise the per-scan budget to fit the observed p99 heap (≥4Gi) and raise
`addressSpaceFactor` (4 is defensible; it is a runaway backstop, not the control). The
existing budget arithmetic in `values.opsadmin.multiacr.yaml` does not absorb this:

| Option | Scans | Uploads | Total vs 10Gi limit |
|---|---|---|---|
| Today | 2 × 2Gi = 4.0Gi | ~5.4Gi | 9.4Gi — fits, but thrashes |
| A: keep pool 2 | 2 × 4Gi = 8.0Gi | ~5.4Gi | 13.4Gi — **needs `limits.memory: 16Gi`** |
| B: pool 1 | 1 × 4Gi = 4.0Gi | ~5.4Gi | 9.4Gi — fits, halves scan concurrency |

Recommend **A**. Observed traffic peaks at 169 pushes/hour, and B's serialisation would
push queue wait straight back into the 30s ceiling — trading one failure mode for the
same one. Raising the node-level ask is the honest cost of scanning multi-GB images.

**Also measure before choosing the number.** `grype`'s peak RSS per image is currently
inferred from one error message. Sample it across the largest repos (the 0.899 GiB
`c3aiops` layer is the largest *layer*, not the largest *image*) so the budget is fitted,
not guessed — this is the same mistake as the old 15 GiB `maxUploadBytes`.

**Verify.** Zero `out of memory` rows; median scan duration back under 30s; no pod
`OOMKilled` at the new limit under peak load.

---

## 4. A retried push re-scans from scratch

**Evidence.** There is no decision/scan cache on the manifest path — `manifest.go` has no
lookup by manifest digest before gating. So a client that times out at 30s and retries
causes a *second* full scan of an identical, content-addressed image.

**Why it matters here.** Steps 2+3 stop wasting work and stop the kills, but the client
that already gave up still sees a failure. Reuse is what makes the retry succeed
immediately, and it compounds: at a 50% failure rate a large share of current load is
almost certainly retries of images already scanned.

**Change.** Before gating, look up a completed decision for the same manifest digest
(content-addressed, so this is sound) within a short freshness window, and reuse it.
Freshness must be bounded by the scanner DB version — `gate_decisions.scanner_db_version`
already exists for exactly this, and `merlin_scanner_db_age_days` is now scraped. Reusing
a decision made with an older vulnerability DB would silently weaken the gate, so the
lookup must require a matching `scanner_db_version`.

**Rejected option: async push (return 202, scan later).** It breaks the fail-closed
contract — the client would receive success before the gate ran, and the registry protocol
gives no place to report a later rejection. Not worth it; steps 2–4 remove the pressure
that motivates it.

**Verify.** Push an unchanged image twice; the second returns fast with no new
`scan_duration` observation. `merlin_scan_duration_seconds_count` should fall relative to
`merlin_requests_total{route="manifest"}`.

---

## 5. The alerter is blind to exactly this outage

The step-5 detectors shipped in `767a66d` would not have told anyone. Worth fixing *after*
1–4, because right now they would only page about a known 50%.

**`infra_error_rate` — silent, and the arithmetic is exact.**
`RateThresholds` defaults are `MinSamples 20`, `MinRate 0.10`, `MinFactor 2`
(`internal/alert/runner.go:88-96`). Live: 72 samples ✓, rate 0.556 ≥ 0.10 ✓, then
`InfraErrorStepChange` applies `if base > 0 && rate < base*MinFactor` → `0.556 < 0.494×2
= 0.988` → **returns nil**. A ~50% failure rate is invisible because it is *stable*.

The `MinFactor` gate exists for a stated reason: "a steady-state failure rate above the
floor alerts on every single run forever". But that is what the 6h `(detector, signature)`
cooldown already handles. **Change:** fire on `MinRate` **OR** `MinFactor`, keeping
`MinSamples`, and add a much higher absolute floor (e.g. `MinRateAlways ≈ 0.25`) that
fires regardless of baseline. Rationale to record: deviation detection cannot see a
failure that was already there when the baseline was measured.

**`novel_error` — silent, plus a normalization gap.** All three signatures are 27–53h old,
so they sit inside the 168h baseline → correctly not novel. But the promotion detail
embeds the image ref, and `Signature()`'s URL rule
(`internal/alert/signature.go`) only strips paths from strings with a scheme —
`c3devops.azurecr.io/c3.ai/dcgm-exporter-fips:4.6.0…` has none, so it survives and every
repo becomes its own signature. Effect: one systemic bug arrives as N per-repo alerts,
each new repo firing as "novel". **Change:** normalize bare `registry/repo:tag` refs the
same way as URLs (keep the registry host, drop repo/tag).

**`killed_scan` — fires, but misattributes.** 72 ≫ threshold 5, so this one *would* have
paged — saying memory pressure, when the median 31.1s says client disconnect. Its scope
comment stakes out parent-vs-child OOM correctly but does not anticipate cancellation as a
third cause. **Change:** once step 2 labels the cause in `error_detail`, split the
detector (or its summary) so `client-abandoned` and `kernel/limit-killed` are never
reported as the same thing.

**Then, and only then, enable it.** The webhook must be patched into `merlin-secrets`
(`externalSecrets.enabled: false` here) per the commented recipe in
`values.opsadmin.multiacr.yaml`. Enabling before 1–4 means a 6-hourly reminder of an
outage nobody has fixed, which trains people to ignore it.

---

## Step 6: re-measure

The point of all of it. After 1–4, the same two queries that produced the table at the top
of this document should show infra_error well under 5%, and each remaining class should be
individually explainable. If the rate does not move, one of the root causes above is wrong
and should be re-derived from the audit table rather than patched around.
