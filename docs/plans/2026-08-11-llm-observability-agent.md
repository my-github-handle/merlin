# Proposal: LLM-Based Observability Agent for Merlin

**Status:** Draft for review
**Date:** 2026-08-11
**Scope:** §0 is the recommendation. §1–§9 are the full analysis that produced it,
including the milestones it argues *against* building yet.

---

## 0. Recommendation (read this section only, if you read one)

**Do not build the agent yet.** The evidence gathered for this proposal argues against
its own headline feature. The realistic plan is roughly one week of work, contains no
LLM, and finishes an already-approved design instead of starting a new one:

| # | Do | Effort | Why |
|---|---|---|---|
| 1 | **Snapshot the audit window** to a TTL-exempt table + fixtures | ~1h, today | The only evidence base that exists, and it expires on a rolling 30-day TTL (§1) |
| 2 | **Bound grype's memory** in the scan path | ~1 day | Closes the only unbudgeted memory consumer in the pod — see the correction below. **Done**, 2026-08-11 |
| 3 | **Finish Changes A + B** of the approved 2026-07-10 design (§0.1) | ~1 day | Already reviewed, never implemented; Change A is what makes the residual class diagnosable. **Done**, 2026-08-11 |
| 4 | `ServiceMonitor` + widen latency histogram buckets + wire `scanner_db_age` | ~half day | Metrics currently don't persist and can't express p95 (§1.1). **Done**, 2026-08-11 (buckets in `2e24d23`) |
| 5 | **Three scheduled ClickHouse queries → Slack**, deduped by a `last_notified_at` row | ~2 days | Novel-`error_detail` detection, `infra_error` step-change, OOMKilled restarts. **Done**, 2026-08-11 (`internal/alert`) — third detector narrowed, see below |
| 6 | **Stop and re-measure** | — | Decide anything further from data, not from this document |

**Correction to an earlier draft of step 2.** That draft claimed bounding grype "removes
~90% of all infra failures." That was overstated, and the distinction matters for what
step 6 will measure:

- What a bound *does* fix: grype was the only unbudgeted memory consumer in the pod.
  Uploads are budgeted (`max_upload_bytes` × `upload_concurrency`, explicitly sized
  against `resources.limits.memory`); scans were not. So concurrent scans raced the
  cgroup limit and the kernel picked a victim — and nothing guaranteed the victim was
  grype. A scan could take the merlin parent down and fail every concurrent push. A bound
  makes the failure *attributable to grype* and *survivable by the parent*. That is worth
  the day on its own.
- What it does *not* do by itself: the scans that were too big are still too big. Bounding
  converts an opaque kernel `SIGKILL` into an attributable grype failure; it does not make
  the scan succeed.
- What reduces the *count* is the concurrency and the per-scan budget — now
  `scan_pool_size: 2` × `memory_limit: 2Gi` in `values.opsadmin.multiacr.yaml`. Picking
  those numbers well needs step 1's snapshot data, so treat the current values as the
  first budgeted guess, not a tuned one.

One implementation note worth carrying forward: the bound is applied as `GOMEMLIMIT` on
the grype child, with `RLIMIT_AS` only as a derived backstop (`internal/limitexec`).
`RLIMIT_AS` alone would have been the wrong instrument — it caps *virtual* address space,
which a Go runtime reserves far in excess of its live heap, so setting it to the memory
budget would have failed scans that were never over budget. `GOMEMLIMIT` is soft:
exceeding the budget makes grype GC harder and scan slower rather than fail, which is the
right failure mode for a fail-closed gate.

Note what step 5 is *not*: no `Source` interface, no five adapters, no incident lifecycle
state machine. A cooldown timestamp per detector buys ~90% of the suppression value
described in §3 Task 3 for ~5% of the code. Build the state machine only if the simple
version demonstrably fails.

**Two corrections to step 5, as built (`internal/alert`, 2026-08-11).**

1. *The third detector is narrower than "OOMKilled restarts."* It is `killed_scan`: grype
   children killed by SIGKILL (`signal: killed` / exit 137), which are visible **only**
   because step 2 made them attributable. A SIGKILL to the merlin **parent** — the actual
   pod OOMKill — writes no audit row at all, by construction: the process is gone before
   the audit write. No ClickHouse query can ever see it. Detecting that needs
   `kube_pod_container_status_last_terminated_reason` from the ServiceMonitor added in
   step 4, or the Kubernetes API (no client-go in `go.mod`). The ClickHouse-visible half
   shipped; the pod-restart half is a step-6 decision.
2. *There is a two-method `Source` interface, deliberately.* The prohibition above was
   against a pluggable adapter layer, and there is none: exactly one implementation
   (`*Store`, one ClickHouse connection) with a compile-time assertion. The interface
   exists so the three detectors and the runner's cooldown logic are unit-testable
   without a database — which is what pinned the failure modes that comments alone would
   not have caught: overlapping windows (novelty can never fire), a suppressed firing
   extending its own cooldown (the finding never resurfaces), and recording a cooldown
   for a message Slack rejected (silence).

Also worth carrying into step 6: `alert_notifications` lives in `internal/alert/schema.sql`,
*not* `internal/audit/schema.sql`, specifically so it does not inherit the 30-day audit
TTL. Expiring suppression rows would re-announce every long-standing finding the moment
its row aged out.

**Deliberately not in the plan:**

- **M2 (auto-mitigation) — do not build.** Three of its four playbooks target bugs
  already fixed in code (`8b528b8`, 2026-08-10, closed both the Valkey key leak and the
  scratch-dir leak) or are one `kubectl` away. The dry-run / circuit-breaker / rollback
  machinery costs more than the toil it removes on a two-replica service.
- **M1 (LLM triage) — probably not worth it, and that is a legitimate finding.** Once
  grype is bounded, §1.2's residual is ~1.2 novel events/day and falling. A five-adapter
  pipeline with detector fan-in and a schema'd incident record, serving a handful of
  events a month, read by the person who wrote the service, is not where the value is.
- **If you want an LLM in the loop, put it on novelty, not triage.** A weekly job that
  normalizes `error_detail`, groups it, and flags strings never seen before catches
  "something new is breaking" — the failure mode humans genuinely miss. That is ~50 lines,
  not a subsystem.

§1–§9 remain below because a reviewer needs to see *why* the larger system was rejected,
and because §1/§1.1/§1.2 (the measured baseline, the telemetry gaps, the residual
arithmetic) are durable regardless of what gets built.

### 0.1 Prior art that must be reconciled first

`docs/specs/2026-07-10-infra-error-observability-design.md` (290 lines, commit `15be83d`,
**"Design approved, pending spec review"**) already designs infra-error observability for
this exact problem. Its status today:

| Change | What | Shipped? |
|---|---|---|
| A | `registry` label + coarse error class (`auth`/`timeout`/`network`/…) on `merlin_acr_push_total`, via `internal/acr/classify.go` | **No** — `acrPush` still has only a `result` label |
| B | New `merlin_requests_total{method,route,status}` | **No** — no such metric exists |
| C | `infra_error` audit column so a 502 is not miscounted as a policy reject | **Yes** — `2a52a84`, 2026-07-21 |

This matters more than it looks. **Change A is precisely the instrument for the one class
this proposal could not explain.** §1.2 identifies 22 ACR-cancels as the most interesting
residual — genuinely unexplained, since the credential-cache fix (`a15447d`) deployed
2026-07-11, the day *before* the measurement window opens. Change A classifies exactly
that failure into `auth` / `timeout` / `network` without a model reading logs. Finishing
an approved design beats starting a new one.

The same document also flagged, and deferred as a follow-up, the resource drift that is
still present: `charts/merlin/values.yaml` limits memory to **2Gi** while the live deploy
runs **10Gi**, called out on 2026-07-10 as "a latent OOM risk for the assemble/scan path
on large images" — one week before the scanner swap that began the OOM kills. Worth being
precise about the implication: the live pod already has 10Gi **and still OOMs ~14x/day**,
so the fix is bounding grype's own memory (or capping scan input size), not raising the
ceiling again.

---

## 1. Why (grounded in current state, not hypotheticals)

Merlin is an admission gate on the image-push path. When it degrades, CI pushes fail
and the failure surfaces to developers as an opaque `502` or a hung `docker push`.
Today, diagnosing that requires a human to hand-correlate four disconnected sources:
pod logs (plain text), the ClickHouse audit store, Prometheus counters, and Helm/K8s
state. The last two incidents in this repo's history each took multi-hour manual
investigation across exactly those four places.

Baseline measured from the live `azplatdevops` / `c3-opsadmin` deployment on
2026-08-11, over `gate_decisions` (2026-07-12 → 2026-08-06, 26 days, 6,389 gate
decisions, 41 distinct repos):

| Class | Count | % of all decisions |
|---|---|---|
| OK (gate completed) | 6,079 | 95.15% |
| **INFRA: grype OOM-killed** (`signal: killed`) | **279** | **4.37%** |
| INFRA: ACR push canceled | 22 | 0.34% |
| INFRA: scan canceled / timeout | 9 | 0.14% |

Policy blocks (a correct, working gate saying "no"): 1,949.

Gate latency for completed decisions: **p50 4.98s, p95 70.5s, p99 121.0s, max 279.8s**.

> **This baseline is perishable.** `retention_days` defaults to 30
> (`internal/config/config.go:154`) and is applied to every audit table as
> `ALTER TABLE ... MODIFY TTL ts + INTERVAL 30 DAY` (`internal/audit/retention.go:18`).
> The 07-12 end of the window has already aged out; the whole window is gone by
> mid-September 2026. See Task 0.1 — the window must be snapshotted before any code
> is written, because every acceptance criterion below is defined against it.

Two things stand out and they shape the whole design:

1. **The dominant failure is one recurring class — and it is a regression, not a
   condition.** 4.37% of all pushes died to grype being OOM-killed (69 on 07-29, 48 on
   07-22, 24 on 08-05). Every one of them is *after* 2026-07-17, when the trivy→grype
   swap shipped (`3179e3e`, `83f1a3b`): 279 failures over ~20 days, **~14/day**, starting
   the week the new exec runner landed. There is no memory bound anywhere in the grype
   path. This is not a long tail of novel mysteries and it is not an observability gap —
   it is an unfinished migration (see §0.1).
2. **p99 gate latency is 121s against a 300s `gate_timeout`.** The margin is ~2.5x,
   so latency creep is a real precursor signal, not a theoretical one.

### 1.1 The blocking prerequisites (must be said up front)

> **Addressed 2026-08-11 (§0 step 4).** The chart now ships
> `charts/merlin/templates/servicemonitor.yaml` (gated `metrics.serviceMonitor.enabled`,
> default off, on in `values.opsadmin.multiacr.yaml`), and `merlin_scanner_db_age_days`
> now has a producer (the grype policy). The paragraph below records the state that
> motivated the work; the "no history to detect on" consequence still holds until the
> scrape has been running long enough to build one — which is what step 6 waits for.

**Nothing currently scrapes Merlin's metrics.** Verified live: `/metrics` on `:9090`
serves ~15 time series, but there is no `ServiceMonitor`, no `PodMonitor`, and
no `prometheus.io/scrape` annotation on the Service or pods — even though
`prometheus-app-prometheus-0` and Grafana are both running in-cluster. The counters
increment in pod memory and are **lost on every restart**.

Consequences that any honest proposal has to state:

- There is **no metric time-series history** to detect on. Prometheus-based anomaly
  detection has no data to read today.
- The metric surface is **4 families, not 15** (`internal/observability/metrics.go`):
  `merlin_push_decisions_total`, `merlin_scan_duration_seconds`,
  `merlin_scanner_db_age_days`, `merlin_acr_push_total`. The ~15 figure is the *series*
  count after histogram buckets and labels expand. There is no per-repo, no
  queue-depth, no staging/scratch and no Valkey metric. So even a perfect scrape path
  leaves `MetricSource` nearly empty until new instrumentation lands — Task 0 is
  necessary, not sufficient.
- **`merlin_scan_duration_seconds` cannot express this workload's latencies.** It is
  registered with `prometheus.DefBuckets` (`internal/observability/metrics.go:32`),
  whose ceiling is **10s**. Observed p50 is 4.98s and p95 is 70.5s, so p95/p99/max all
  land in `+Inf` and `histogram_quantile` returns nonsense above 10s. Any
  latency detector must read ClickHouse `duration_ms` until the buckets are widened.
- `merlin_scanner_db_age_days` has no producer (`SetScannerDBAgeDays` has zero
  non-test call sites) but it **is** consumed: `internal/dashboard/data.go:214` reads
  it into `vm.ScannerDBAgeDays`, so operators are shown a hard `0` today. It is
  already actively misleading, not latently so.
- Logs are unstructured `log.Printf` text (`v2 GET /v2/ -> 401 (0B, 0s)`), collected
  by filebeat. Usable, but requires parsing rather than field access.

Therefore **ClickHouse is the only durable, queryable signal source today** — subject
to its 30-day TTL — and everything here sits primarily on it. Task 0 addresses both
prerequisites: preserving the audit window before the TTL reclaims it (0.1), and making
the metric path scrapeable and honest (0.2). Only 0.1 blocks work starting; 0.2 is what
makes anything time-series-shaped possible later, and even then only after the metric
surface itself grows.

### 1.2 What the LLM half is actually worth (the uncomfortable arithmetic)

The 4.37% grype-OOM class is the load-bearing evidence for this whole proposal, and it
is **a known, unfixed bug** — §6 concedes as much, saying the root cause "needs a code
fix (bounding grype's memory)." That has a consequence the proposal must not dodge:

**Subtract the classes we already recognize, and the residual novel-failure rate is
31 decisions over 26 days — roughly 1.2 events per day**, from the 22 ACR-cancels and
9 scan timeouts. That, not 4.37%, is the workload an LLM triage layer exists to serve.

Two conclusions follow, and they restructure the plan:

1. **Bound grype's memory first, as a separate workstream.** It is the highest-value
   change available and it is not an observability project. Building a triage agent
   whose headline metric is "detects the bug we chose not to fix" measures the wrong
   thing, and that metric evaporates the day the fix ships. Fix it, then re-measure
   what failure actually looks like.
2. **Split the deterministic half out as its own milestone (M0) and ship it first.**
   All six detectors below are ClickHouse queries plus a few K8s reads. As alert rules
   they are a small fraction of the total effort and capture most of the operational
   win: you learn about grype OOM within 15 minutes instead of never. The LLM adds
   correlation narrative on ~1 event/day. Bundling both means the cheap, certain value
   cannot ship until the expensive, speculative value does.

This is not an argument against the agent. It is an argument for ordering the work so
each stage is justified by what the previous stage measured, and for M1 being explicitly
optional if M0's residual toil turns out to be small.

---

## 2. Design principle: LLM for judgment, code for detection

The central risk in "LLM observability agent" proposals is using a model where a
`WHERE` clause belongs. That is slow, expensive, and non-deterministic on exactly the
recurring cases that matter most.

So the split is explicit:

- **Deterministic code detects.** Threshold/rule evaluation over ClickHouse and (once
  scraped) Prometheus. Reproducible, cheap, testable, alertable. This is all of M0.
- **The LLM triages.** Given a detected anomaly plus gathered evidence, it does the
  part humans are slow at: correlating heterogeneous sources, ranking hypotheses,
  writing an explanation, and citing the evidence. This is M1.

### 2.1 The agent is a signature-discovery tool, not a fixture

Every known signature gets a deterministic classifier and the LLM handles the residue.
Follow that to its conclusion: **whenever the LLM correctly triages a novel failure, the
right response is to promote that finding to a deterministic detector** — at which point
the LLM never sees that class again. If the system works, its own scope shrinks
monotonically toward zero.

That reframing matters in two ways:

- **Success looks like declining LLM invocation**, not a growing dashboard. The agent is
  an amortizing investment in signature coverage, not a permanent operational tenant.
- **If promotion never happens, you are paying a model to re-derive the same conclusion
  forever.** So promotion is a *required output* of triage, not a nice-to-have: every
  novel incident closed as understood must produce either a new detector or a written
  reason why it cannot be expressed as one (see M1 Task 3).

---

## 3. Milestone 0 — Deterministic detection & alerting (no LLM)

**Goal:** Merlin's known failure classes page a human within minutes, with zero model
involvement and zero write access. This milestone is independently valuable and should
ship on its own merits whether or not M1 follows.

### Task 0: Close the telemetry gap (prerequisite)

**0.1 — Snapshot the replay window (do this first, before any other work).**
Every acceptance criterion in this document is defined against 2026-07-12 → 2026-08-06,
and that data expires on a rolling 30-day TTL. Export `gate_decisions` and
`vulnerability_findings` for the window to a TTL-exempt table (`gate_decisions_replay`)
*and* to a checked-in fixture file, so detector tests are hermetic and the §1 baseline
stays reproducible. Everything downstream depends on this; it is hours of work and it is
on a clock.

**0.2 — Fix the metric surface.**
- Add a `ServiceMonitor` to `charts/merlin` (gated `metrics.serviceMonitor.enabled`,
  default off to stay compatible with clusters lacking Prometheus-Operator CRDs).
- Replace `DefBuckets` on `merlin_scan_duration_seconds` with buckets extending past
  `gate_timeout` (e.g. `1, 2.5, 5, 10, 30, 60, 120, 180, 240, 300`). Without this the
  histogram is blind above 10s, which is where every interesting latency lives.
- Wire `SetScannerDBAgeDays`, **or** delete the gauge *and* the dashboard field that
  reads it (`internal/dashboard/data.go:214`, `vm.ScannerDBAgeDays`). Wiring it is the
  recommendation — the dashboard already promises the value.

**0.3 — Optional.** Switching to structured `slog` JSON logging so consumers read
fields instead of regex-parsing. Meaningful diff; propose separately.

### Task 1: Signal adapters (read-only, no LLM)

A `Source` interface with five implementations, each returning typed evidence. M0 needs
Audit, Cluster and Valkey; Metric and Log are thin until 0.2/0.3 land.

| Adapter | Reads | Purpose |
|---|---|---|
| `AuditSource` | ClickHouse `gate_decisions`, `vulnerability_findings` | Durable ground truth: outcomes, `error_detail`, latency |
| `MetricSource` | Prometheus HTTP API | Rates/trends (post-Task 0.2; thin until instrumentation grows) |
| `LogSource` | pod logs via K8s API | Recent unstructured context around a window |
| `ClusterSource` | K8s API: pod status, restarts, `lastState.terminated`, Helm revision | OOMKills (exit 137), rollout correlation |
| `ValkeySource` | `DBSIZE`, `SCAN` + `TTL` sampling on the staging keyspace | Required by `ValkeyKeyGrowth`; no other adapter can see the leak class |

All read-only credentials. `ClusterSource` gets a `get`/`list`-only Role — no `delete`,
no `exec`, no `patch`. `ValkeySource` is read-only here (`DBSIZE`/`SCAN`/`TTL` only);
the write path it needs for the M2 `expire-leaked-keys` playbook is a **separate**
credential introduced with that playbook.

### Task 2: Deterministic detectors

Baseline-derived, encoding the numbers above. **Source is named per detector on
purpose** — several are only implementable against ClickHouse, because the Prometheus
surface cannot express them (§1.1):

| Detector | Source | Condition | Rationale |
|---|---|---|---|
| `InfraErrorRate` | Audit | `infra_error = 1` rate over 15m > 3x trailing-7d baseline | Baseline is 4.85% infra overall; catches step-changes |
| `GrypeOOM` | Audit | any `error_detail LIKE '%signal: killed%'` | Known top class; exact signature, no inference needed |
| `GateLatencyCreep` | Audit (`duration_ms`) | p99 over 30m > 200s | p99 is 121s vs 300s timeout; 200s = approaching cliff. **Not** Prometheus: the histogram's bucket ceiling is 10s |
| `PodRestart` | Cluster | `restartCount` increase, or `lastState.terminated.reason=OOMKilled` | Caught the 2026-08-06 double-replica OOMKill |
| `ScanStall` | Audit + Log | decisions/hour drops to 0 while pushes arrive in logs | Silent-stall case metrics alone miss |
| `ValkeyKeyGrowth` | Valkey | `DBSIZE` monotonically rising over 24h with no decline | The 91k-key leak class; cheap to check, was invisible for weeks |

Trailing-baseline windows are bounded by the 30-day audit TTL; no detector may assume
history beyond it.

Each detector is a pure function over a fetched window → unit-testable with fixtures,
no live cluster needed.

### Task 3: Incident identity, lifecycle, and suppression

This is the part that decides whether the output is usable, and it is easy to skip.
`GrypeOOM` fired **69 times on 2026-07-29**. Naively that is 69 incidents — about 10 a
day across the window — which blows any false-positive budget with *true* positives and
makes "alert fatigue" a certainty rather than a risk.

So incidents are not decisions. Define:

- **Identity key** = `(detector, signature, affected_scope, open_window)`. Two firings
  with the same key are the *same* incident, and the second one updates it (bumping
  `occurrence_count`, `last_seen_at`) rather than creating a new record.
- **Lifecycle**: `open` → `ongoing` → `resolved` (detector stops firing for a cooldown
  period) → optionally `reopened`. Only the `open` transition notifies.
- **Suppression**: while an incident is `ongoing`, repeat firings are recorded silently.
  A separate `escalated` state fires if an `ongoing` incident exceeds a duration or
  occurrence threshold — an incident nobody fixed for 6 hours deserves a louder signal
  than the same incident firing 69 times.
- **Flap damping**: N consecutive clean evaluations required before `resolved`.

This also disambiguates the false-positive criterion, which is otherwise unanswerable: a
repeat firing of an already-`open` incident is **neither** a true nor a false positive —
it is not an incident at all. FP rate is counted over `open` transitions only.

### Task 4: Alerting surface

Detector firings write to a new ClickHouse table (`incidents`) with the lifecycle fields
above, and notify on `open`/`escalated` via a thin Slack/Teams sink. No LLM, no
narrative — the alert says which detector fired, the signature, the scope, and links to
the evidence query.

Rendering incidents in the existing dashboard **requires authentication on that surface
first** — see §9.1; it has none today.

### M0 acceptance criteria (falsifiable)

Validated by **replay against the snapshotted window** (Task 0.1):

1. Replaying 2026-07-12 → 2026-08-06 flags **≥ 95%** of the 279 grype-OOM decisions.
   This is near-tautological — the detector *is* the signature — so it verifies plumbing,
   not judgment.
2. **Zero** incidents raised on the 1,949 policy blocks (a working gate saying "no" is
   not an incident — the single most important false-positive guard). Mechanically
   enforceable, not a judgment call: `gate_decisions.infra_error` already exists
   (`internal/audit/schema.sql`, written at `internal/audit/clickhouse.go:133`), so the
   guard is a `WHERE infra_error = 1` filter at the detector boundary.
3. The 279 grype-OOM decisions collapse to **≤ 15 incidents**, not 279 — proving the
   identity/suppression logic in Task 3 works on the real distribution.
4. False-positive rate < 1 per day on the replay window, counted over `open`
   transitions only.
5. Detectors are unit-tested with fixtures; no test requires a live cluster.

---

## 4. Milestone 1 — LLM triage (read-only)

**Goal:** for the residual failures M0 detects but cannot explain, a human opens one
artifact that already says what broke, which evidence proves it, and what to do — with
zero write access.

**Entry condition, deliberately explicit:** M0 has run in production long enough to
measure residual toil, and that toil is large enough to justify this. Given §1.2's
~1.2 novel events/day, **M1 may correctly turn out not to be worth building.** Deciding
that on M0's data is a success, not a failure.

### Task 1: Detector fan-in

Real degradation does not fire one detector. The 2026-08-06 OOMKill would trip
`PodRestart`, `InfraErrorRate`, `GateLatencyCreep` and `ScanStall` more or less at once.
Four incidents describing one event is worse than none.

So triage is invoked on a **correlated group**: detectors firing within a window over
overlapping scope are collapsed into one triage call, with the full set of firings as
evidence. This is also where the LLM genuinely earns its place — "these four symptoms
are one cause" is precisely the correlation humans are slow at, and no threshold rule
expresses it.

### Task 2: Triage record

Gather evidence from all five adapters for the incident window, then one LLM call
produces a structured record (JSON-schema enforced):

```
incident_id, detected_at, severity, title
triggering_detectors[] : the correlated group from Task 1
classification         : known_signature | novel
hypotheses[]           : {cause, confidence, supporting_evidence[], contradicting_evidence[]}
blast_radius           : affected repos/identities/push count
recommended_action     : human-readable, ranked
evidence_refs[]        : ClickHouse query + row ids, log line refs, pod/Helm revision
proposed_signature     : a candidate deterministic detector, or why none is possible
--- filled in by a human, not the model ---
human_verdict          : correct | partially_correct | wrong | unreviewed
actual_cause           : free text
confirmed_by, confirmed_at
```

Hard requirements, because an unfalsifiable triage report is worse than none:

- **Every claim carries an evidence reference.** No citation → the field is dropped.
- **`contradicting_evidence` is mandatory**, forcing the model to look for
  disconfirmation rather than confabulating a tidy story.
- **Known signatures bypass the LLM** for classification and use a static explanation;
  the LLM only adds blast-radius narrative. Deterministic where determinism is free.
- **`proposed_signature` is mandatory on every `novel` incident** (§2.1). Triage that
  does not feed the deterministic layer is triage you will pay for again.
- The model **never** sees credentials; adapters run queries, the model sees results.

### Task 3: Ground-truth capture (the part that makes M2 possible)

The `human_verdict` block above is not documentation — it is the measurement substrate
for the entire M1→M2 transition. M2's precondition is "a human confirmed the triage was
correct," and without stored verdicts that claim rests on recollection and cannot be
queried.

Therefore:

- Every incident that reaches `resolved` **requires** a verdict before it can be closed;
  `unreviewed` closures are counted and reported, not silently allowed.
- The M2 gate becomes a query, not an opinion:
  `SELECT countIf(human_verdict='correct')/count() FROM incidents WHERE ...`.
- `actual_cause` versus the model's top hypothesis is the accuracy signal that tells you
  whether the LLM half is worth its cost over time — the same data that justifies
  *retiring* it once signature coverage is good (§2.1).

### Task 4: Output surface

Triage records extend the M0 `incidents` table rather than introducing a second store.
Notification is the same thin sink, now carrying the narrative. The artifact is the
product; delivery is plumbing.

### M1 acceptance criteria (falsifiable)

1. The 2026-08-06 double-replica OOMKill produces **one** incident (not four) naming
   memory exhaustion, citing exit 137, **without** a human hint.
2. **Novel-path hold-out.** With the known-signature rules disabled, replay the 22
   ACR-cancel and 9 scan-timeout/canceled decisions. A human reviewer judges whether
   each triage record identified the actual cause with correct citations. Target:
   **≥ 70% correct, 0% confidently-wrong** (a wrong cause asserted with high confidence
   and no `contradicting_evidence` is a hard failure, worse than "unknown").
3. p95 triage latency < 60s from detection.
4. Every `novel` incident in the hold-out carries a `proposed_signature`, and a reviewer
   judges ≥ 50% of them implementable as deterministic detectors.
5. No incident can be closed without a `human_verdict`.

Criterion 2 decides whether the LLM half earns its place at all — if novel triage fails
it, stop at M0 and keep the deterministic detectors.

---

## 5. Milestone 2 — Mitigate (write access, tightly bounded)

M2 only begins once M1 has run read-only long enough to trust its classifications.
Precondition, now measurable via Task 3's stored verdicts: **≥ 2 weeks of M1 in
production**, meeting the FP bar, with `human_verdict = 'correct'` on **every** incident
in that window and zero `unreviewed` closures. Automating a bad classifier is how you
turn a small outage into a large one.

### Design stance: no free-form remediation

The LLM does **not** author remediation commands. It **selects** from a registry of
pre-authorized, individually-reviewed, idempotent playbooks. This is the difference
between a system whose blast radius is bounded by code review and one bounded by a
prompt.

Each playbook declares: preconditions, the action, expected observable effect,
verification query, reversibility class (below), and a blast-radius bound.

### Candidate playbooks (each earns its place from observed history)

| Playbook | Trigger | Action | Reversibility |
|---|---|---|---|
| `reclaim-scratch` | scratch > 80% of volume, dirs older than `DefaultScratchMaxAge` | **Invoke the existing sweeper** with a tightened `maxAge` — not a second deletion path | **Irreversible** — deleted dirs do not come back |
| `expire-leaked-keys` | `ValkeyKeyGrowth` + keys with `TTL -1` | `EXPIRE <key> <ttl> NX` — **never `DEL`** | **Irreversible** — a TTL stamp cannot be un-set meaningfully |
| `restart-saturated-replica` | replica OOMKilled ≥ 2x in 30m and pool saturated | Rolling delete of one pod, respecting the 375s grace | Reversible (state re-converges) |
| `lower-upload-concurrency` | sustained OOM pressure | Reduce `upload_concurrency` toward a floor | Reversible (restore prior value) |

Two constraints that are easy to get wrong:

- **`reclaim-scratch` must not be a second actor.** `staging.SweepScratch` already runs
  in-process from `internal/app/app.go:266` with `DefaultScratchMaxAge`, so the playbook
  adds nothing by re-implementing deletion — and two independent deleters over the same
  directory tree is a race. Its only legitimate value-add is *parameterizing* the
  existing sweeper (tighter cutoff under disk pressure). The 15.7G incident predates
  that in-process sweeper; if it recurs *with* the sweeper running, that is a bug to fix
  in the sweeper, not a symptom to mitigate on a timer.
- **`expire-leaked-keys` requires `EXPIRE ... NX`, i.e. Valkey/Redis ≥ 7.0.** Pin and
  assert the server version as a playbook precondition — on an older server the flag is
  rejected and the playbook must fail closed, never fall back to bare `EXPIRE` (which
  would overwrite a live TTL) or to `DEL`. It also needs the Valkey **write** credential
  introduced with this playbook; `ValkeySource` stays read-only.

`expire-leaked-keys` deliberately encodes the safer of the two options used during the
manual cleanup: TTL-stamping rather than deleting, so a genuinely in-flight push cannot
lose its staging state.

### Mandatory guardrails

1. **Dry-run first, always.** Every playbook renders its intended change and the
   verification it will run, before acting.
2. **Approval tiers:** `auto` versus `approval-required`. Start with **everything** in
   `approval-required` and promote individually on evidence.
3. **Rate limit + circuit breaker.** Max N actions/hour; on repeat firing, stop and
   escalate. Repeated mitigation of the same symptom means the diagnosis is wrong —
   the correct behavior is to stop and get a human, not to keep pulling the lever.
4. **Verify, and roll back only where rollback exists.** Post-action, always re-run the
   detector; unresolved → escalate. But rollback is *not* universally available and the
   guardrail must not pretend otherwise — you cannot un-delete a scratch directory or
   un-expire a key. So playbooks split into two classes with different obligations:
   - **Reversible** (`restart-saturated-replica`, `lower-upload-concurrency`): must
     implement and test a rollback; unresolved verification triggers it automatically.
   - **Irreversible-but-provably-dead-data** (`reclaim-scratch`, `expire-leaked-keys`):
     no rollback exists, so the burden shifts entirely to the **precondition proof** —
     the playbook must demonstrate, from evidence, that the data it touches cannot be
     live (age beyond `DefaultScratchMaxAge`; `TTL -1` on a key whose push completed).
     Verification failure escalates and **disables the playbook**; it cannot retry.
   No playbook may be registered without declaring its class.
5. **Full audit trail** to ClickHouse: trigger, evidence, playbook, dry-run output,
   result, verification, reversibility class, and rollback outcome where applicable.
   Non-negotiable — this is a security-gate component.
6. **Never touch the policy decision path.** The agent may fix *infrastructure*; it
   must never alter what the gate allows or blocks, weaken a threshold, or retry a
   policy rejection into a pass. Fail-closed stays fail-closed.

### M2 acceptance criteria

1. Every playbook has a test proving its precondition and effect, plus — for reversible
   playbooks — its rollback. Irreversible playbooks instead have a test proving the
   precondition rejects live data.
2. Dry-run output for each is reviewed by a human before that playbook is enabled.
3. Circuit breaker demonstrably halts a repeat-firing loop in test.
4. An irreversible playbook whose verification fails is demonstrably disabled, not
   retried.
5. Zero actions taken against the policy path (enforced structurally, not by prompt).

---

## 6. Explicit non-goals

- **Not** a replacement for Prometheus alerting. M0 *is* threshold alerting, done over
  the only durable source available; it should stay that cheap. M1 adds correlation and
  explanation on top.
- **Not** an autonomous fixer of code defects. It mitigates operational symptoms. The
  grype-OOM root cause needs a code fix (bounding grype's memory) and that fix should
  ship *before* this, not be replaced by it (§1.2).
- **Not** a chat interface. The product is the triage artifact, not a bot to converse
  with.
- **Not** permanent. If §2.1 works as intended, the LLM's scope shrinks as signature
  coverage grows, and retiring it is a success condition.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Confident-but-wrong triage | Mandatory citations + `contradicting_evidence`; known signatures bypass the LLM; hold-out criterion scores confidently-wrong as a hard failure |
| Automating a misdiagnosis | M2 gated on stored `human_verdict` data, not recollection; approval-required by default; verify-or-escalate |
| Alert fatigue from *true* positives | Incident identity + suppression (M0 Task 3); FP counted over `open` transitions only; criterion 3 caps 279 firings at ≤ 15 incidents |
| Building the agent to detect a bug we should fix | §1.2: bound grype's memory as a separate, earlier workstream; M1 entry is conditional on measured residual toil |
| LLM cost never amortizes | `proposed_signature` mandatory on novel incidents; success = declining invocation |
| Validation substrate expires before use | 30-day audit TTL; Task 0.1 snapshots the replay window to a TTL-exempt table + fixtures before any implementation |
| Task 0 mistaken for sufficient | Only 4 metric families exist, and the latency histogram is blind above 10s; §1.1 states this so `MetricSource` is not over-relied on |
| Guardrail that cannot be honored | Reversibility classes (guardrail 4) — irreversible playbooks carry a precondition-proof burden instead of a fictional rollback |
| Agent becomes an attack surface on a security gate | Read-only through M1; no credentials in prompts; no playbook may touch the policy path |

## 8. Sequencing

0. **Task 0.1 — snapshot the replay window.** On a clock (30-day TTL), blocks every
   acceptance criterion, hours of work. Nothing else starts first.
1. **Bound grype's memory** — separate workstream, highest value available, and it
   changes what the rest of this proposal is sized against (§1.2). Note the live pod
   already runs 10Gi and still OOMs; this is a bound on grype, not a bigger limit.
2. **Finish Changes A + B of the approved 2026-07-10 design** (§0.1) — reviewed but never
   implemented, and Change A is the instrument for the unexplained ACR-cancel class.
3. **Task 0.2** (scrape path + latency buckets + `scanner_db_age`) — small, unblocks
   time-series work.
4. **M0** (adapters → detectors → incident identity → alerting), validated by replay
   against the snapshot. Ship it; it stands alone. §0 recommends the reduced form —
   three queries and a cooldown row — over the full build.
5. **Re-measure residual toil** with M0 running and the grype fix in. Decide whether M1
   is justified. A "no" here is a legitimate outcome.
6. **M1** triage layer, validated by the novel-path hold-out — *only* if step 5 said yes.
7. Run M1 read-only ≥ 2 weeks with verdicts recorded; measure the M2 gate as a query.
8. **M2** playbooks one at a time, each starting in `approval-required`. §0 recommends
   against reaching this step at all.

## 9. Open questions for review

1. **Model choice / hosting.** Does this call an external API, or must it stay in-cluster
   for a security-gate component? This materially changes the design and I do not want
   to assume it.
2. **Scope of `ClusterSource`.** Merlin's namespace only, or the wider cluster? Wider
   context improves correlation but broadens the read surface.
3. **Audit retention.** 30 days is fine for compliance-free operational triage but caps
   every trailing baseline the agent can compute, and it is why Task 0.1 exists. Should
   `retention_days` be raised for `gate_decisions` specifically (it is the cheap table —
   `vulnerability_findings` is the bulky one), or is snapshot-on-demand the answer?
4. **Who owns the grype memory fix?** §1.2 makes it a precondition for sizing this work,
   but it is a scanner-path change, not an observability change. If it is not going to
   happen, say so — that materially strengthens the case for M0 and weakens M1's.

### 9.1 Resolved (was an open question)

**Output surface.** Previously asked whether to reuse the existing dashboard.
Recommendation: **not without auth first.** Verified there is no app-level
authentication anywhere in `internal/dashboard/*.go`, and incident records expose
materially more operational detail than gate decisions do — hypotheses, pod state, Helm
revisions, blast radius. Publishing that to an unauthenticated surface fronting a
security gate is the wrong default. Either add auth to the dashboard as part of M0
Task 4, or render incidents on a separately-gated surface. The `incidents` table itself
is unaffected by this choice.
