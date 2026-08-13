# Refactoring plan

**Status:** proposed, 2026-08-13
**Relationship to [2026-08-13-gate-reliability.md](2026-08-13-gate-reliability.md):** that
plan fixes a live ~50% infra-error rate. This one does not compete with it. Two items here
are *prerequisites* for doing that work safely, one rides along with it, and the rest wait.
Refactoring a fail-closed gate while it is half-broken, for tidiness alone, is not a
trade worth making.

## Measurements, 2026-08-13

Source 9,109 lines / tests 12,081 lines (1.33:1 — healthy). **No file exceeds the 800-line
limit**; the largest is `internal/app/app.go` at 523. So this is not a file-size problem.
It is a *function-size and construction* problem.

Functions over the 50-line guideline:

| Lines | Function | File |
|---|---|---|
| **331** | `BuildWithBackends` | `internal/app/app.go:142` |
| 99 | `main` | `cmd/merlin/main.go:18` |
| 82 | `PassRate` | `internal/dashboard/view.go:28` |
| 81 | `NewMetrics` | `internal/observability/metrics.go:28` |
| 65 | `Build` | `internal/app/app.go:77` |
| 55 | `NovelErrors` | `internal/alert/detect.go:79` |
| 53 | `bootstrapSchema` | `internal/audit/clickhouse.go:53` |
| 50 | `extractTar` | `internal/staging/assemble.go:197` |
| 50 | `ClassifyPushError` | `internal/acr/classify.go:36` |

Coverage on the packages this plan touches — **this drives the ordering**. All figures are
from a hermetic `go test`, which is the honest default but *understates* any package with
tagged integration tests whose backend is absent; R3 is the worked example of how badly.

| Package | Coverage | vs 80% target |
|---|---|---|
| `internal/config` | 92.4% | ✅ |
| `internal/observability` | 88.9% | ✅ |
| `internal/ingress/docker` | 86.9% | ✅ |
| `internal/dashboard` | 76.0% | ⚠️ |
| `internal/staging` | 70.5% | ❌ |
| `internal/promote` | ~~64.4%~~ → 82.7% / 98.4% | ✅ **R3 done** — and 64.4% was a missing *backend*, not missing tests (see R3) |
| `internal/app` | **28.4%** | ❌❌ ← where the 331-line function lives |

**The inversion is the point:** the largest, most tangled function in the codebase sits in
the least-tested package, and the worst production bug sits in the second-least-tested one.

## Root cause: objects are constructed by mutation

`internal/ingress/docker/handler.go` exposes **11 setters** — `SetRequestObserver`,
`SetPromoter`, `SetMaxPendingPromotions`, `SetMaxUploadBytes`, `SetUploadConcurrency`,
`SetUploadWait`, `SetPool`, `SetGateTimeout`, `SetScratchBaseDir`, `SetRegistryAuth`,
`SetTokenHandler` — invoked ~16 times from `app.go`. A `Handler` is therefore only valid
after an unwritten sequence of calls, and nothing in the type system says which are
required or in what order.

Three consequences, all of them observed rather than theorised:

1. `BuildWithBackends` is a **331-line assembly script** because it *is* the missing
   constructor.
2. There are **two divergent constructors**. `Build` (65 lines) and `BuildWithBackends`
   (331) wire different subsets and return different arities —
   `(*http.Server, *http.Server, error)` versus
   `(*http.Server, *http.Server, *http.Server, func(), error)`. When the alerter was added
   in `767a66d` it went into one and deliberately not the other; that decision was correct
   for that change, but the divergence is now permanent and undocumented in the types.
3. Both return servers **positionally**. Three bare `*http.Server` values in a row means
   every caller has to remember that #1 is the gate, #2 metrics, #3 dashboard. Swapping two
   compiles cleanly and would serve the dashboard, which has no auth, on the gate port.

This also violates the repo's own immutability rule (`rules/common/coding-style.md`:
"ALWAYS create new objects, NEVER mutate existing ones").

---

## R0 — Build the net before touching the wiring *(prerequisite)*

**Why first.** Refactoring a 331-line function at 28.4% coverage is not refactoring; it is
rewriting untested production wiring and hoping. Nothing else in R1 may start until this
lands.

**Change.** Cover `internal/app` construction to ≥80%: for each backend, assert what
`BuildWithBackends` wires — that the ACR push observer reaches `outcome`, the pool honours
`gate_timeout`, the alerter starts only with a webhook and is absent from `Build`, closers
run in reverse order, and each `err` path returns the wrapped message. `internal/app`
already has `alerts_test.go` as a model; these are table tests against a config, not live
backends.

**Verify.** `go test -cover ./internal/app/...` ≥ 80%, and every new test fails if you
delete the line it covers (mutate-and-check by hand — coverage that passes with the
behaviour removed is decoration).

---

## R1 — One constructor, named returns, no setters

**Depends on R0.** ~2–3 days.

**Change, in three behaviour-preserving commits:**

1. **Named result struct.** Replace the positional multi-return with
   `type Servers struct { Gate, Metrics, Dashboard *http.Server; Close func() }`. Mechanical,
   compiler-verified, and it removes the port-swap class of bug outright.
2. **Config struct in place of setters.** Give `docker.New` a `HandlerConfig` carrying what
   the 11 setters set, and validate required fields once in the constructor. Keep the
   setters as thin deprecated wrappers during the transition so tests migrate incrementally
   rather than in one commit; delete them in the final commit of this item.
3. **Decompose `BuildWithBackends`** into per-concern helpers (`buildStaging`,
   `buildAudit`, `buildPromotion`, `buildAuth`, `buildServers`), each returning its
   component plus a closer. `Build` then becomes a thin call into the same helpers with
   backends stubbed — which is what makes the divergence *visible in one place* instead of
   duplicated across two functions.

**Explicitly preserved:** `Build`'s hermetic contract (no live backends, no goroutines, no
alerter). The goal is to make that contract legible, not to remove it. Record it as a
documented predicate, not an accident of which function you edited.

**Verify.** No behaviour diff: `helm template` output unchanged, and a dry-run boot against
the live ConfigMap produces byte-identical startup logs (the probe technique from this
session: `docker create` → `docker cp` config → `docker start -a`).

---

## R2 — Untangle the manifest gate path *(ride along with reliability step 2)*

**Do not schedule this separately.** `internal/ingress/docker/manifest.go` (461 lines) is
exactly where reliability steps 2 and 4 land. Refactoring it first means editing it twice;
refactoring it after means editing tangled code under outage pressure. Do them in one
change, refactor commit first, behaviour commit second, so review can separate them.

**What is tangled.** One function currently interleaves: request-context derivation
(`:144`), pool acquisition with its own timeout budget (`:287`), scan invocation with a
second budget (`:306`), queue-wait observation, saturation-vs-disconnect error triage,
publish-mode selection (`SyncPublish` vs promoter), job field assembly, and cleanup
(`:239`). Five of those need to change for steps 2 and 4.

**Change.** Extract the gate execution into a named unit that takes an explicit context
policy — which is precisely the seam reliability step 2 needs
(`context.WithoutCancel` for the scan, request context for the response) — and separate
"decide" from "publish" from "hand off". The 86.9% coverage here is the reason this is
lower-risk than R1 despite being higher-churn.

**Verify.** The existing `manifest_flow_test.go` (548 lines) and
`promote_handoff_test.go` (359) pass untouched *before* the behaviour commit. If the
refactor commit needs test edits, it is not a refactor.

---

## R3 — Lift `promote` coverage before fixing it *(prerequisite for reliability step 1)*

**Status: DONE 2026-08-13.** 64.4% → **82.7%** hermetic, **98.4%** with a live Valkey.

**The 64.4% was wrong, and how it was wrong matters more than the number.** It measured
an *absent dependency*, not absent tests. `internal/promote/valkey_integration_test.go`
already held a conformance suite covering the queue — behind `//go:build integration`,
skipping unless `MERLIN_VALKEY_ADDR` is set. `mage integration` runs the tag but supplies
no backend, so the tests **skipped silently** and the target passed. Simply providing a
Valkey moved coverage 64.4% → 83.2% with no new tests at all. Lesson to keep: a skip that
exits 0 is indistinguishable from a pass, and this one hid 30 statements of the Lua that
makes `Claim` atomic.

**What was added.**

1. `worker_faults_test.go` — a `faultQueue` decorator injecting Enqueue/Claim/Ack/Recover
   failures, because every consequential worker decision lives in a branch an
   always-working queue cannot reach. `worker.go` and `promote.go` are now at **100%**:
   the claim-error backoff (and its cancel path), the negative-`RecoverAfter` default, a
   failed recovery sweep, published-but-unacked cleanup, both requeue-vs-ack orderings,
   retire-with-failed-ack, Cleanup errors, nil `Recorder`, and the zero-value defaults.
2. `valkey_offline_test.go` — every queue method's outage branch against an unreachable
   address, asserting the *wrapping* (operation + push ID). Those messages are the entire
   audit trail for a queue whose clients were already answered 201.
3. Five integration cases for the server-only branches: parking a payload with no
   `push_id` (it is in no hash, so Ack and Recover can never see it), a stamp with no
   payload, a corrupt claimed payload, an unparseable stamp treated as ancient, and
   `NewValkeyQueueAtAddr`'s success path.
4. `mage testPromoteQueue` — starts a throwaway Valkey in Docker and runs the suite.
   **Cluster-enabled, one node owning all 16384 slots.** Not cosmetic: the deployed
   Valkey reports `cluster_enabled:1`, `Claim`/`Recover` are multi-key EVALs, and a
   non-cluster Valkey accepts them happily. A plain single-node container would have
   passed the entire suite while the CROSSSLOT bug was live.

**Three statements remain uncovered, deliberately.** `Enqueue`'s marshal error is provably
dead (`Job` is only strings, `[]string`, `[]byte`, `uint8` — `json.Marshal` cannot fail);
`Ack`'s second `HDEL` and `Recover`'s requeue-script error require one command to fail
while its already-covered sibling on the same connection succeeds. Reaching them needs a
fault-injecting proxy, which is more machinery than the branches are worth.

**The 404-terminal test is NOT here.** It was listed under this item, but terminal-vs-
retryable classification *does not exist yet* — it is what reliability step 1 introduces.
A test asserting zero retries on a `BlobNotFound` is therefore that step's RED test, not
R3's verification, and putting it here would have meant shipping either a failing test or
a behaviour change inside a test-only commit (ground rule 2). R3's job was the net; the
net is in place, mutation-checked.

**Mutation-checked, per R0's rule.** Four production lines were inverted one at a time —
ack-anyway after a failed requeue, negative window not defaulted, skip cleanup when ack
fails, default budget 3→5 — and each made its test fail. Coverage that survives the
behaviour being removed is decoration.

---

## R4 — Smaller, independent items

Each is a self-contained afternoon; none blocks anything else. Ordered by value.

| Item | Change | Note |
|---|---|---|
| `main` (99 lines) | Move orchestration into `app.Run(ctx, cfg)`; leave flag parsing + exit codes in `main` | Makes the startup path testable at all |
| `PassRate` (82) | Split the aggregation from the presentation arithmetic | `dashboard` at 76% — add cases while splitting |
| `NewMetrics` (81) | Table-driven registration | Cosmetic; declarative already. Lowest value here — do it only if touching the file anyway |
| `bootstrapSchema` (53) | Read the DDL per statement from the embedded `schema.sql` rather than in-function | Removes the second place schema lives |
| `ClassifyPushError` (50) | Table of (matcher → class) | Straight win; pure function, already covered |
| `config.go` (385) | Split `validate*` per section into `config_validate.go` | File is under limit; do only if it grows |

---

## Explicitly NOT refactoring

Named so nobody "fixes" them later:

- **Two ClickHouse stores** (`internal/audit/clickhouse.go`, `internal/alert/clickhouse.go`).
  Looks like duplication; is deliberate. The alerter's `alert_notifications` must not
  inherit the audit tables' retention TTL, and merging them would re-couple exactly what
  was separated. Documented in `internal/alert/schema.sql`.
- **The `Source` interface in `internal/alert`** with one implementation. A compile-time
  assertion with a single impl is normally a smell; here it is what lets the detectors be
  tested without a database. Recorded as a deliberate correction in the step-5 plan.
- **Large test files in `ingress/docker`** (548, 432, 414 lines). Test files are allowed to
  be long when each case is independent; splitting them buys nothing and loses grep-ability.
- **`internal/limitexec`'s trampoline.** Genuinely unusual (a process re-execing itself),
  but the alternative is a shell or helper binary on a distroless image. The design comment
  explains it; leave it. Its *constants* change in reliability step 3 — that is tuning, not
  refactoring.

## Ground rules

1. **A refactor commit changes no test.** If existing tests need edits, it is a behaviour
   change wearing a refactor's clothes — split it.
2. **One package per PR**, and never a refactor and a behaviour fix in the same commit
   (R2 is the one interleaved item, and even there the commits are ordered and separate).
3. **No refactor into a package under 80% coverage** — build the net first (R0, R3). This is
   the rule the measurements above exist to enforce.
4. **Reliability plan takes priority on contention.** If R1 and a production fix want the
   same file in the same week, the fix wins and R1 rebases.

## Sequencing summary

| Order | Item | Gate |
|---|---|---|
| ~~1~~ | ~~R3 (promote coverage)~~ **DONE** | net in place; reliability step 1 is unblocked |
| 2 | R2 + reliability step 2 | one change, two commits |
| 3 | R0 (app coverage) | unblocks R1 |
| 4 | R1 (one constructor) | after R0 |
| 5 | R4 items | any time, independently |
