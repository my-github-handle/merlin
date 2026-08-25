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
decoration this plan warns about:** *(two of the three were made in R1 commit 3, 2026-08-24 —
see `TestCloserStackRunsInReverseOrder` and `TestOutcomeMetricsAlsoCountACRPushes`.)*

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
3. **Decompose `BuildWithBackends`** ✅ **DONE 2026-08-24** (see below) into per-concern
   helpers (`buildStaging`, `buildAudit`, `buildPromotion`, `buildAuth`, `buildServers`),
   each returning its component plus a closer. `Build` then becomes a thin call into the same
   helpers with backends stubbed — which is what makes the divergence *visible in one place*
   instead of duplicated across two functions.

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

### Commit 3 — `BuildWithBackends` decomposed (landed 2026-08-24)

`BuildWithBackends` went **331 → 92 lines** and `Build` **→ 49**; the extracted helpers live
in the new `internal/app/components.go`. The remaining body is the *sequence* and nothing
else: validate, then one call per concern, each owning its own resources and its own closer.

| Helper | Owns |
|---|---|
| `validateProductionConfig` | the 8 required-field checks, order preserved exactly |
| `buildAuth` | per-tenant JWKS authenticators + refreshers, resolver, registry-token issuer, client creds |
| `buildStaging` | the session store (no closer — neither client exposes one) |
| `buildPromotion` | the Valkey promotion queue |
| `buildAudit` | ClickHouse writer, auditor, report reader (+ one closer for all three) |
| `newMetrics` / `buildPolicyEngine` / `buildOutcome` | registry and sinks, the policy engine, the decision outcome |
| `buildIngress` | the `HandlerConfig` literal and `docker.New` |
| `buildDashboard` | the dashboard server **and the decision recorder** |
| `sweepScratchAtStartup` / `startPromoteWorker` / `startSamplers` | the startup sweep and the three goroutines |
| `buildServers` | the three `http.Server` values and the composed `Close` |

**The last construction-by-mutation in this package is gone.** `outcome.Recorder` used to be
patched *after* the outcome was built, because whether decisions are teed into the dashboard
feed is only known once the dashboard exists. `buildDashboard` now **returns** the recorder
and is called *before* `buildOutcome`, so the outcome — and therefore the handler and the
promotion worker — is complete at construction. Behaviour-equivalent because `dashboard.New*`
neither dials nor fails fatally, and the mutation happened before any request was served.
`TestBuildDashboardReturnsTheRecorderInUse` pins the three cases (`off`, `""`, a real addr).

**Both assertions R0 recorded as impossible are now made — and mutation-checked.**

1. `TestCloserStackRunsInReverseOrder`. The closers were a local slice inside a 331-line
   function and `cleanup()` returned nothing, so the order was unobservable. It is
   load-bearing, not cosmetic: the auditor drains its queue into the ClickHouse writer on
   `Close`, so a writer released first silently discards every buffered decision — scans that
   ran and left no record. Reversing `closeAll`'s loop fails with
   `close order = [writer auditor reader], want [reader auditor writer]`.
2. `TestOutcomeMetricsAlsoCountACRPushes`. `Handler.acrPushObserver` reaches the ACR push
   counter by **type assertion** on `outcome.Metrics`, so a sink implementing only
   `MetricsObserver` compiles, wires, passes every push test, and silently stops writing
   `merlin_acr_push_total`. The test asserts the assertion succeeds *and* scrapes the series
   back, because a sink wired to a different registry would pass the assertion alone.
   Wrapping `outcome.Metrics` in a `MetricsObserver`-only type fails with
   `outcome.Metrics (app.onlyPushMetrics) is not an ACRPushObserver`.

**One divergence was documented rather than fixed.** `Build` passes no `IDGen`, so pushes get
`docker.generatePushID`, which degrades to a timestamp when `crypto/rand` fails;
`BuildWithBackends` passes this package's, which panics. That is a real difference between the
paths, but this commit preserves behaviour, so it is enumerated on `Build`'s doc comment and
pinned by `TestBuildOutcomeIDGenIsTheCallersChoice` — the reconciliation stays a decision
instead of becoming drift.

**Verification, run rather than asserted:**

- **`helm template` byte-identical** (working tree vs `git stash`).
- **Production-path startup logs identical.** The earlier probes booted `Build`, not
  `BuildWithBackends` — `cmd/merlin` selects the production path on `MERLIN_MODE=production`,
  and without it the probe verified the hermetic path only. Re-run properly: the live
  ConfigMap with the three ports retargeted and `staging.valkey_addr` / `audit.clickhouse_dsn`
  pointed at throwaway containers (the same cluster-mode Valkey and version-pinned ClickHouse
  `mage testAppWiring` provisions), plus a dummy `AZURE_FEDERATED_TOKEN_FILE` so the ACR
  credential constructs off-cluster. Both binaries then reach a **fully wired production
  boot** — all five startup lines, all three listeners bound. Sorted and with timestamps
  stripped, the diff is empty. The three `listening on` lines interleave nondeterministically
  *within* each binary across repeat runs (three runs of each showed two different orders per
  binary), so raw-order equality is not the property to assert here.
- **Registered metric set identical**, scraped from `/metrics` on both binaries: the same 7
  series. This is the check that would catch a `newMetrics` extraction that registered
  collectors on a registry nothing serves.
- `go test -race ./...` clean; `mage integration` green across all five packages.

App coverage: **80.4% → 80.5%** live (`mage testAppWiring`), **39.3% → 44.3%** hermetic. The
hermetic jump is the point — helpers reachable without live backends are now testable
individually, which is what `components_test.go` exercises.

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
| ~~`main` (99 lines)~~ ✅ **DONE 2026-08-25** | Move orchestration into `app.Run(ctx, cfg)`; leave flag parsing + exit codes in `main` | `main` 114 → 75 lines, all of it env + exit codes. `Run(ctx, cfg, Builder)` takes the builder as a parameter — the mode strings stay in `main`, and injecting it is what makes the lifecycle testable. 7 new tests in `run_test.go` covering the drain, which had **no test at any level** before. Three deltas, each deliberate and pinned: the drain budget is parsed **before** the build (a bad `shutdown_timeout` no longer opens ClickHouse, Valkey, Blob and the JWKS refreshers first); a dead gate/metrics listener is **returned** instead of `log.Fatalf`-ed from inside a goroutine, so the audit buffer is flushed on the way out; and `Close` runs **once**, not twice. Mutation-checked: deriving the drain context from the already-cancelled signal context, parsing the budget late, and dropping the deferred `Close` each fail a test. Live SIGTERM against the production path drains and exits 0 with logs identical to `HEAD`'s |
| ~~`PassRate` (82)~~ ✅ **DONE 2026-08-25** | Split the aggregation from the presentation arithmetic | **The 82 was a measurement artifact**: `view.go` was 109 lines, `PassRate` began at 28, and the tool counted 109 − 28 + 1 to EOF through nine trailing type declarations. `PassRate` was 6 lines. The item's *intent* held — the arithmetic worth splitting was inline in `data.go` (`toStatsVM`'s percentage, `Overview`'s `ok/(ok+errc)*100`), and the package's actual long function was `Report` at 62. Net first (`6debe64`, 76.0 → 87.8%), then the split (`e2d1d2a`, → 91.7%): one `pct()` in `percent.go`, view models in `viewmodel.go` as pure functions, `data.go` 260 → 182. `Report` is now 12 lines and no longer full-scans the findings table on a by-ref miss. Dead `Service.counterValue` deleted. **Found while netting it, deliberately not fixed:** `handleStream` never flushes the response head until the first decision arrives, so an SSE client blocks in `Do()` on an idle feed — pinned as-is in `sse_test.go`'s header |
| ~~`NewMetrics` (81)~~ ✅ **DONE 2026-08-25** | ~~Table-driven registration~~ → registration at the point of definition, in four groups by what each metric measures | Net first (`649a086`, 88.9 → 94.4%), then the refactor (`aefb5d1`, → 97.0%). 81 → 11 lines. **The plan's table was rejected with a reason**: 10 heterogeneous collectors (CounterVecs with 1/2/3 labels, 4 Histograms with 4 bucket sets, 3 Gauges) need a kind discriminator and a switch — trading compile-time types for a runtime one and moving each metric's rationale away from it. The one real defect, the duplicated `MustRegister` list, is bought by a nine-line `registered[T]` helper. `TestEveryCollectorFieldIsRegistered` walks the struct by reflection rather than naming ten fields, because naming them rebuilds the list that goes wrong; a constructed-but-unregistered collector records perfectly and is never scraped, with no error and no panic. Mutation-checked under both mechanisms |
| ~~`bootstrapSchema` (53, really 47)~~ ✅ **DONE 2026-08-25** | ~~Read the DDL per statement from the embedded `schema.sql`~~ — **already implemented**; `splitStatements(schemaSQL)` had been there all along | What was actually wrong: three interleaved concerns — which statements, which connection each needs, and running them — so none could be tested without a ClickHouse. Body now 15 lines saying only the part that needs a server; `databaseGroup` and `schemaGroups` are pure and at 100% (`de0e3b1`, `492b0aa`). Every error string preserved byte for byte, verified by probe — `bootstrapGroup` exists precisely so collapsing two loops onto one connection did not collapse their errors into one message. **The gate could not be met as written** and this is a stated exception: audit's 19.5% hermetic against 71% live is 30 query functions that need a real ClickHouse, and no work on this function moves it. Verification standing behind it is `be2bc38`'s DDL net + the probe + the integration suite. `be2bc38` is the find: the DDL runs on **every pod start** and nothing checked it — six properties netted hermetically, the load-bearing one being that a table added to `schema.sql` but missing from `ttlStatements` retains its rows **forever, silently**. All six mutation-checked |
| ~~`ClassifyPushError` (50, really 45)~~ ✅ **DONE 2026-08-25** | ~~Table of (matcher → class)~~ → four numbered ordered steps; only the status row is a real table | Note "already covered" was wrong: `acr` was at **56.0%**, with `Push`, `PushManifest`, `PushBlob` and **all of `fake.go`** at 0.0% — the entire publish half of the gate rested on the live E2E run. Net first (`59cb92a`, → 88.1%, `ClassifyPushError` to 100%), then the refactor (`c5a9323`). The net's headline is the ordering property `PushManifest`'s doc comment claims and nothing asserted: an index PUT whose sub-manifests were never pushed must **fail**, which is what stops a rejected image being published by reference. Runs against go-containerregistry's own in-process registry — inside a module already required, so no new dependency and no network. The order is the subject of the refactor: `*url.Error` implements `Timeout()`, so it *is* a `net.Error` whatever it wraps, and a 401 inside one is auth only because the status arm sits above the network arm. Mutation-checked. **Also corrected a false comment**: `net.ErrClosed` *is* a `net.Error` (`poll.errNetClosing`), so step 4 is unreachable for every standard error; kept, since removing it would change behaviour for a third-party error that reports `Is(net.ErrClosed)` without satisfying the interface |
| `config.go` (385) | Split `validate*` per section into `config_validate.go` | **Gate not met — deliberately not done.** Still exactly 385 lines, the number this plan recorded; it has not grown. Revisit when it does |

**Measurement errors found across R4, for whoever sizes the next batch.** The line
counts above were taken to EOF rather than to the closing brace, so any function
followed by type declarations reads long: `PassRate` was 6 lines, not 82. Three real
long functions are absent from this table entirely — **`handleUpload` at 146 lines,
the largest function in the codebase**, and `applyDefaults` and `validate` at 61 each
in the very `config.go` whose row says it is under the limit.

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
| ~~4~~ | ~~R1 (one constructor)~~ **DONE** | all four commits landed: 1 (`Servers`), 2 (`HandlerConfig`), 2b (setters deleted), 3 (`BuildWithBackends` decomposed). Both R0-deferred assertions — closer ORDER and the ACR push observer reaching `outcome` — are now made and mutation-checked. 80.5% live / 44.3% hermetic |
| 5 | R4 items | any time, independently |
