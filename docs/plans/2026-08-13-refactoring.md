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
tagged integration tests whose backend is absent. R3 was the first worked example; R0 showed
it was systemic (see below), and `internal/app` is the extreme case — 43 points between the
hermetic and provisioned figures.

| Package | Coverage | vs 80% target |
|---|---|---|
| `internal/config` | 92.4% | ✅ |
| `internal/observability` | 88.9% | ✅ |
| `internal/ingress/docker` | 86.9% | ✅ |
| `internal/dashboard` | 76.0% | ⚠️ |
| `internal/staging` | ~~70.5%~~ → 77.3% | ⚠️ backend supplied, no new tests |
| `internal/alert` | ~~67.1%~~ → 81.6% | ✅ backend supplied, no new tests |
| `internal/audit` | → 71.0% | ⚠️ backend supplied, no new tests |
| `internal/promote` | ~~64.4%~~ → 82.7% / 98.5% | ✅ **R3 done** — and 64.4% was a missing *backend*, not missing tests (see R3) |
| `internal/app` | ~~28.4%~~ → 39.3% hermetic / **82.1%** live | ✅ **R0 done** |

**Four of those rows moved without a single new test being written.** `mage integration`
ran the `integration` tag but set neither `MERLIN_VALKEY_ADDR` nor `MERLIN_CLICKHOUSE_DSN`,
so five of the six tagged files skipped and the target reported success. R3 found this in
`promote` and called it a lesson; it was in fact a *target* defect affecting every tagged
suite, and it is now fixed at the source — `Integration` provisions both backends, runs
each package against **its own ClickHouse database**, and `checkIntegrationPackages` fails
if a package grows a tagged test without being registered, so the list cannot rot back into
silence. Per-package databases are not tidiness: the first provisioned run failed in
`internal/alert` because `go test ./...` runs packages in parallel and `internal/audit` was
inserting rows into the database `alert` was counting.

**The inversion is the point:** the largest, most tangled function in the codebase sits in
the least-tested package, and the worst production bug sits in the second-least-tested one.

## Root cause: objects are constructed by mutation

*(Fixed 2026-08-24 by `HandlerConfig` — commits `ff35f03` and 2b below. The diagnosis is
kept as written, because it is what the design of `New` answers to.)*

`internal/ingress/docker/handler.go` exposed **11 setters** — `SetRequestObserver`,
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

**Status: DONE 2026-08-14.** 28.4% → **82.1%** with backends (`mage testAppWiring`),
**39.3%** hermetic. R1 is unblocked.

**Why first.** Refactoring a 331-line function at 28.4% coverage is not refactoring; it is
rewriting untested production wiring and hoping. Nothing else in R1 may start until this
lands.

**The plan's own premise was wrong, and it mattered.** This item said "these are table
tests against a config, not live backends." They cannot be. `BuildWithBackends` is 158 of
the package's 257 statements (61.5%) and cannot be *entered* without live clients —
`NewValkeySessionStoreWithTTL` pings on construction and `NewClickHouseWriter` bootstraps
its schema. With every other function in the package at 100%, the hermetic ceiling is
**44.7%**. So ≥80% was arithmetically unreachable the way this item described, and the
work split in two:

1. `wiring_derived_test.go` — hermetic, for everything *derived* from config rather than
   dialled. 28.4% → 39.3%. The case worth keeping is the PARTIAL per-tenant image-age
   override: a tenant setting only `enabled` must inherit the default threshold, because a
   zero-value copy would set `thresholdDays: 0` and a 0-day threshold rejects every image
   ever built.
2. `wiring_live_test.go` (tag `integration`) + `mage testAppWiring` — 82.1%.

**Assertions go through the returned surface, never a private field.** This is what makes
it a net for R1 rather than a cast of the current implementation: R1 replaces the
positional returns with a `Servers` struct and the 11 setters with a `HandlerConfig`, so a
test reaching into handler internals would have to be rewritten by the very refactor it
guards — which by ground rule 1 would prove it was never a refactor.

**Three things the item asked for are NOT asserted, and pretending otherwise would be the
decoration this plan warns about:**

- **Closers run in reverse order.** The `closers` slice is private and `cleanup()` returns
  nothing, so order is unobservable from outside the package. What IS asserted: `cleanup()`
  returns within 10s, and does so after the parent context is cancelled. R1 gives each
  helper its own closer — assert order there, where it becomes visible.
- **The pool honours `gate_timeout`.** Observable only by driving a scan to its deadline,
  which `internal/ingress/docker` already does at 87.3% (`manifest_abandoned_scan_test.go`).
  Duplicating it here would need a full push through the app-level handler for no new
  information.
- **The ACR push observer reaches `outcome`.** `outcome` is a local inside
  `BuildWithBackends`. The registry-sharing half of this claim *is* covered (below); the
  push-observer half waits for R1 to make it a named seam.

**Two findings the tests produced rather than confirmed:**

- **An unreachable JWKS at boot does NOT fail the build.** `keyfunc.NewDefaultCtx` logs the
  failed refresh and retries in the background, so the gate starts and rejects every token
  until the set loads — still fail-closed, at request time instead of boot time. This
  matters beyond the test: three pods restarted `exit=2` during the `46f0ce5` rollout
  carrying exactly that message, so **the keyfunc is not what exited** and the JWKS-at-boot
  item in the reliability plan needs a different root cause.
- **The gate answers 404, not 401, to an unrecognised Host.** Routing is per-tenant by host
  (`<prefix>.<acr.baseDomain>`). Correct — a 401 challenge to an unknown host would solicit
  credentials for a tenant this gate does not serve — and now pinned.

**Verify (met).** `mage testAppWiring` → 82.1%. Mutation-checked by breaking one production
line at a time:

| Mutation | Result |
|---|---|
| dashboard built even when `dashboard_addr: off` | caught (6 tests) |
| gate and dashboard servers swapped in the return | caught — the exact bug the positional returns invite |
| metrics server handed a fresh registry | **NOT caught at first** — see below |

The third mutation is the one worth recording. The original test asserted that
`merlin_promote_pending` *appeared* in `/metrics`, and it passed happily against a
brand-new registry — because constructing metrics over any registry registers the same
names, all reading zero. Presence of a metric name proves nothing about which registry
serves it. The test now drives a request through the **gate** and then requires a
**positive** `merlin_requests_total` sample from the **metrics** server, which no separate
registry can satisfy. Exactly the decoration this item's Verify clause was written to
catch, caught by it.

---

## R1 — One constructor, named returns, no setters

**Depends on R0.** ~2–3 days.

**Change, in three behaviour-preserving commits:**

1. **Named result struct.** ✅ **DONE 2026-08-24** (see below). Replace the positional
   multi-return with
   `type Servers struct { Gate, Metrics, Dashboard *http.Server; Close func() }`. Mechanical,
   compiler-verified, and it removes the port-swap class of bug outright.
2. **Config struct in place of setters.** ✅ **DONE 2026-08-24**, in two commits (see
   below). Give `docker.New` a `HandlerConfig` carrying what the 11 setters set, and
   validate required fields once in the constructor. The setters stayed as thin deprecated
   wrappers for one commit so the ~90 test call sites migrated separately rather than in the
   same diff as the constructor; commit 2b deleted them.
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

### Commit 1 — `Servers` (landed 2026-08-24)

`Build` returns `(Servers, error)`; `BuildWithBackends` returns `(Servers, error)`. Zero
production behaviour change, and the verification was run rather than asserted:

- **Startup logs are identical.** Built `HEAD` in a throwaway `git worktree` and the working
  tree side by side, rendered the live ConfigMap (`helm template -s templates/configmap.yaml`
  against `values.opsadmin.multiacr.yaml`), retargeted only the three port fields, and booted
  both binaries against it. The two log sets differ only in the *interleaving* of
  `Merlin listening` and `Metrics listening`, which are emitted by two concurrent goroutines
  and race the same way in both builds — sorted, the diff is empty. This substitutes for the
  plan's `docker create` probe, which was the technique available when the plan was written;
  a local worktree gives the same before/after pair without a registry round-trip.
- **`helm template` byte-identical** (nothing under `charts/` was touched, confirmed rather
  than assumed).
- `mage integration`: app 81.9%, audit 71.0%, alert 81.6%, promote 98.5%, staging 77.3%.
  `go test ./...` clean.

App coverage moved 82.1% → **81.9%**. That is not a lost assertion: the same tests now run
over a handful of extra statements (the struct literals in each return). Worth stating rather
than rounding away, because a refactor that quietly *drops* coverage is exactly what this
number is here to catch.

**Two ground-rule tensions, called out rather than glossed:**

1. **"A refactor commit changes no test" — this one edits 12 call sites.** Changing a return
   from five values to one necessarily edits every caller, tests included. What matters is
   that no *assertion* changed: every R0 test still checks the same behaviour through the
   same returned surface, only spelled `built.Gate` instead of `main`. That is the property
   R0 was built for, and it held.
2. **Two assertions were strengthened, deliberately.** `TestBuildWithBackendsArityCompiles`
   asserted only that a five-value signature compiled — a tautology the compiler already
   enforced, and meaningless once the arity is one. It is now
   `TestFailedBuildReturnsNothingToUse`, which pins the real hazard: a failed build returns
   the **zero** `Servers`, every field nil including `Close`, so a caller cannot serve a
   half-wired gate and cannot double-release what `fail()` already closed. Separately,
   `TestBuildIsHermeticAndComplete/starts no alerter` argued from the signature ("Build
   returns no closer, so it cannot own a goroutine") — an argument this commit invalidates,
   since `Servers.Close` is now non-nil for the hermetic build too. It counts goroutines
   instead. Both are stricter than what they replaced; neither weakens to fit the refactor.

**One design decision worth recording:** `Servers.Close` is a **no-op, not nil**, for the
hermetic `Build`. A caller forced to ask which constructor produced its `Servers` before it
can release them has gained nothing over the positional return. `main` lost its
`cleanup = func() {}` branch as a result.

### Commit 2 — `HandlerConfig` (landed 2026-08-24)

`docker.New(HandlerConfig) (*Handler, error)` now builds the handler in one call. Both
`Build` and `BuildWithBackends` use it; the 11 setters remain as `Deprecated:` wrappers so
this package's ~10 test files migrate in a separate commit.

**This commit is NOT purely behaviour-preserving, and that is the point of it.** `New`
*adds* four validations that had no equivalent anywhere:

| Rejected config | What it silently did before |
|---|---|
| no `Resolver` | nil-deref on the first request — the host→tenant map is the security boundary |
| `RegistryIssuer` without `TokenRealm` or `Service` | `WWW-Authenticate` advertised an empty realm, so the client had nowhere to fetch a token and the push stopped with **no error logged anywhere in Merlin** |
| `MaxPendingPromotions` without `Promoter` | `promotionBacklogFull` returns false when `promoter == nil` — the disk bound was inert |
| `UploadWait` without `UploadConcurrency` | `acquireUploadSlot` returns immediately when `uploadSlots == nil` — the wait budget was inert |

Each of those is a value an operator can put in the ConfigMap and reasonably believe is in
force. Startup is the cheapest place to learn otherwise, so all four are now startup
failures rather than gaps.

The couplings are **one-directional**: only the dependent half is rejected. `Promoter`
without a bound, `UploadConcurrency` without a wait, `GateTimeout` without a `Pool`
(`runScan`/`gateBudget` use it pool or no pool), and `RegistryIssuer` without a
`TokenHandler` (`TokenRealm` is an absolute URL — another process may serve it) all stay
legal. `TestNewAcceptsPartialButCoherentConfigs` pins that, so a later tightening cannot
quietly reject a working production config.

**New tests** in `handler_config_test.go`, covering behaviour that did not exist before:
`TestNewRejectsIncoherentConfigs` (the four rules, each asserting the error *names* the
field), `TestNewAcceptsPartialButCoherentConfigs`, `TestNewLeavesUploadSlotsNilWhenUnbounded`
(a cap-0 channel blocks forever, so getting this wrong turns "unbounded" into "shed every
upload"), `TestNewRegistersTokenRouteOnlyWhenConfigured`, and
`TestNewMatchesTheSettersItReplaces` — a field-by-field comparison of a handler built both
ways. That last one is the whole equivalence claim: it was mutation-checked by dropping
`scratchBaseDir` from `New` and confirming it fails with the field name. It carries a
`NumField() == 21` guard, because `reflect` cannot read unexported fields and a field wired
by only one of the two paths is precisely the bug the hand-written comparison would miss.
It deletes itself when the setters go.

**One ordering move in `app.go`.** Building the handler once requires its promoter at
construction, but `promote.NewValkeyQueueAtAddr` was dialled ~100 lines later. Only that
dial moved — up beside the session store, not the whole tail. Error precedence is unchanged
and was checked against the `wiring_live_test.go` failure table: it hits the same Valkey the
session store has already reached, so an unreachable Valkey still surfaces as
`"session store"` and an unreachable ClickHouse still as `"audit writer"`.

App coverage moved 81.9% → **80.4%** (two new error branches in `BuildWithBackends`
returning `Servers{}`, not lost assertions); still above the 80% floor.
`internal/ingress/docker` 87.3% → **87.8%**. `mage integration` green across all five
packages.

### Commit 2b — the setters deleted (landed 2026-08-24)

`NewHandler` and all 11 `Set*` methods are gone. ~90 call sites across 13 test files in
`internal/ingress/docker` now build a `HandlerConfig` literal. Two helpers keep that from
being 90 four-line blocks:

- `mustNewHandler(t, cfg)` — every test in this package builds a config that is coherent by
  construction, so `New`'s error is a bug in the *test*, not a case under test. The
  rejections are covered once, in `handler_config_test.go`.
- `buildIntegrationHandler*` grew `tweaks ...func(*HandlerConfig)` (`withPromoter`,
  `withMaxPendingPromotions`, `withGateTimeout`). Variadic, so every existing caller is
  unchanged — the alternative was threading four more parameters through three helper
  levels.

**Two tests changed subject rather than being deleted.**

`TestNewMatchesTheSettersItReplaces` compared two construction paths; one path no longer
exists. The useful residue is *"does `New` wire every field the config carries"*, which is
exactly the failure this whole change targets — a field that reads back as configured in the
ConfigMap and does nothing. So it became `TestNewWiresEveryConfiguredField`: all 18 fields
populated with non-zero values, each checked to arrive. It keeps the `NumField() == 21`
guard, and it was mutation-checked again after the rewrite by dropping
`scratchBaseDir: cfg.ScratchBaseDir` from `New` — it fails naming that field.

`TestDockerTokenHandshake` passed `TokenRealm: ""` under a comment claiming "realm filled
below via server URL", which it never did — the test reconstructed the URL itself and so
never exercised the challenge a docker client actually follows. `New` rejects that now, so
the test uses `httptest.NewUnstartedServer` (whose listener exists before `Start()`, making
the address known before the handler is built), asserts the challenge advertises that realm,
and then **follows the advertised realm** for step 2. A forced change that made the test
stronger.

Two rationales that lived only in deleted setter comments moved into the `HandlerConfig`
field docs, since that is now the only place an operator reads: "shedding a push is
recoverable (docker retries); filling the volume fails every concurrent push at assemble
time" (`MaxPendingPromotions`) and "the scan `Pool` is deliberately NOT reused: it is sized
for Grype CPU, and sharing it would make uploads and scans starve each other"
(`UploadConcurrency`).

`internal/ingress/docker` 87.8% → **88.0%**; app unchanged at 80.4%. `go test -race` clean
on both packages; `mage integration` green across all five. The dated plan and spec records
under `docs/` still name the deleted setters on purpose — they are records of what was true
when written, not live documentation.

---

## R2 — Untangle the manifest gate path *(ride along with reliability step 2)*

**Status: DONE 2026-08-14.** Refactor `a440b59`, behaviour `92edcac` — two commits, in
that order, as required.

`handleManifest` (253 lines of body) is now the sequence and nothing else; the phases it
used to interleave are named units: `readManifestPush` → `manifestPush`, `stageImage` →
`stagedImage`, `gateRequestFor`, `runGate`/`runScan` → `gateRun`, `publication`,
`logGateOutcome`, `writeDecision`. Two details worth knowing, because both were forced by
the code rather than chosen:

- `stageImage` cleans up its **own** failed assemble. The handler's cleanup defer cannot
  be registered before it holds a `stagedImage`, and the old inline version relied on a
  defer that was already in scope.
- `publication.handedOff` replaces the `promoted` closure variable, so ownership of the
  staged bytes is a field on the thing that transfers them. That is also what made the
  behaviour commit's publish-context change a two-line edit in one place.

The context policy landed as three named funcs — `waitContext`, `scanContext`,
`publishBudget` — which is exactly the seam step 2 needed: its whole behaviour change is
`context.WithoutCancel` inside `scanContext` and `publication.run`.

**Verify (met).** The refactor commit touched only `manifest.go`: `git show --stat a440b59`
is one file, and every test in the package passed untouched (87.0% statements, from 87.1%
— same tests over more statements). The behaviour commit then added
`manifest_abandoned_scan_test.go` and one test *helper* (`buildIntegrationHandlerWithRunner`,
so a test can supply a grype runner that blocks mid-scan); package coverage 87.3%.

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
| ~~2~~ | ~~R2 + reliability step 2~~ **DONE** | `a440b59` refactor + `92edcac` behaviour; live verification still owed |
| ~~3~~ | ~~R0 (app coverage)~~ **DONE** | 82.1% live / 39.3% hermetic; R1 unblocked |
| 4 | R1 (one constructor) | **in progress** — commits 1 (`Servers`), 2 (`HandlerConfig`) and 2b (setters deleted) landed; next is decomposing `BuildWithBackends`; assert closer ORDER and the ACR push observer reaching `outcome` once helpers own their closers |
| 5 | R4 items | any time, independently |
