# Async Promote Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Draft for review
**Date:** 2026-08-11
**Goal:** Make the Docker manifest PUT return response headers in under 30 seconds so `docker buildx build --push` stops timing out against the gate, without letting an unscanned image reach ACR.

**Architecture:** Today `handleManifest` holds the HTTP response headers across the entire publish pipeline — `PutManifest` → `Assemble` → pool wait → `Gate` → `Apply` (which includes the full ACR blob+manifest push). Both push clients cap that wait at 30s, so the window must shrink below 30s. This plan instruments the pipeline first (Task 1), then moves the **ACR promotion** off the critical path (Tasks 2–5), and only moves the **scan** off it (Task 6) if measurement proves scan+assemble alone cannot fit.

**Tech Stack:** Go 1.x, ClickHouse (audit), Valkey (staging blob + session store), Prometheus, Docker Registry V2 protocol.

---

## Global Constraints

- **30-second hard ceiling on response headers.** BuildKit's `util/resolver` sets `ResponseHeaderTimeout: 30 * time.Second` in a hardcoded struct literal; moby's classic push transport does the same independently. Neither is configurable via `buildkitd.toml`, daemon flags, or env vars. Treat 30s as physics, and budget to 15s to leave slack for TLS, ingress, and slot contention.
- **No unscanned image may become pullable from ACR.** Any design where the ACR push precedes the verdict is rejected outright.
- **Registry V2 has no "pending" manifest state.** A manifest PUT returns `201` or an error. There is no third option, so any async design encodes pending-ness *outside* the push response.
- **`Docker-Content-Digest` must be echoed on every 2xx manifest response** (`manifest.go:296-299`) or the client fails the commit with "invalid checksum digest format".
- **Pod restarts are frequent** (OOMKills were ~14/day pre-`8b528b8`). Any queue holding work between the 201 and the verdict must survive process death, or pushes vanish silently and CI pollers hang forever.
- **Audit writes are buffered and asynchronous** (`internal/audit/buffer.go`: `Record` is non-blocking, flushed by `run()`). A decision is not immediately queryable after the gate completes.
- **Scan concurrency is 2, and cannot be raised.** `values.opsadmin.multiacr.yaml:104` sets `scanPoolSize: 2` for c3devops, budgeted in the same file as `memoryLimit 2Gi × scanPoolSize 2 ≈ 4.0Gi` against a 10Gi pod limit already carrying `~5.4Gi` of upload budget. Raising the pool requires raising the memory limit proportionally; matching a 37-push burst would need ~74Gi. Treat 2 slots as fixed.
- **Offered load is bursty, not the ~14/day the pool was sized for.** The `scanPoolSize: 2` rationale in that file reads "At the observed push rate (~14/day) scan concurrency is not the throughput constraint." A gate push submits ~37 images at once, which invalidates that premise. Any latency budget must be computed for the *tail* push of a burst, not the median push.
- **Merlin is multi-tenant, and tenant identity travels by host prefix — never by repo.** `tenant.PrefixFromHost` takes the single leading label of the request host and `staticResolver.ForHost` looks it up in a prefix-keyed map (`internal/tenant/resolver.go:26`). Two tenants may host the same repo name with different ACR registries and credentials. Anything that leaves the request goroutine must carry the tenant prefix explicitly, because the host is gone by then and the repo is not a substitute.
- Go rules apply: `gofmt`/`goimports`, wrap errors with `%w`, `go test -race ./...` must pass.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/observability/metrics.go` | Modify: widen scan histogram buckets; add assemble, queue-wait, and ACR-push observers |
| `internal/router/pool.go` | Modify: no logic change; queue wait is observed by the caller around `Acquire` |
| `internal/staging/assemble.go` | Modify: no logic change; timing is observed by the caller |
| `internal/ingress/docker/manifest.go` | Modify: split the blocked window into measured phases; hand off to the promoter |
| `internal/ingress/docker/outcome.go` | Modify: accept an injected `pushID`; split `Apply` so the ACR push is separable from decision-rendering |
| `internal/promote/promote.go` | Create: `Promoter` interface + durable-queue-backed implementation |
| `internal/promote/worker.go` | Create: the background worker that drains the queue, pushes to ACR, records the final decision |
| `internal/promote/queue.go` | Create: Valkey-backed persistent queue (`Enqueue`/`Claim`/`Ack`/`Recover`) |
| `internal/ingress/docker/report.go` | Modify: add a `pending` state to `reportEnvelope` so a poller can distinguish "not scanned yet" from "no such image" |
| `internal/app/app.go` | Modify: construct and start the promoter/worker; wire into the handler |
| `docs/CI.md` | Modify: correct the false "set your client timeout generously" guidance; document the poll step |
| `docs/specs.md` | Modify: restate the push contract to match whichever variant ships |

---

## Task 1: Make the blocked window measurable

Nothing else in this plan can be justified until the blocked window is attributed. Today one of its six phases is measured.

The window is the **image-manifest PUT only** — blob uploads are separate requests that complete before it. Inside `handleManifest`:

| Phase | Cost model | Instrumented today |
|---|---|---|
| Read body + `classifyManifest` | ms (manifest is KBs) | n/a |
| `PutManifest` (Valkey completeness check) | ms–100s of ms | no |
| `Assemble` (blob read + gunzip + tar-extract + OCI layout) | O(image size), local disk | **no** |
| `pool.Acquire` — **queue wait for 1 of 2 scan slots** | O(burst size ÷ slots) × scan time | **no — captured nowhere** |
| `Gate` (grype) | seconds–minutes | yes, audit `DurationMS` |
| `Apply` → ACR push of all blobs + manifest | O(image size), network to Azure | **no** |

Two specific blind spots:

- `merlin_scan_duration_seconds` uses `prometheus.DefBuckets` (`metrics.go:33`), top bucket 10s, so every real scan lands in `+Inf` and p95 is unrecoverable.
- `gateStart` is taken **after** `Acquire` returns (`manifest.go:262`) — deliberately, per `pool.go:45-48` ("queue wait must not consume scan time"). The side effect is that queue wait appears in no metric and no audit column, even though with 2 slots against a 37-push burst it is the expected dominant term (see Task 2).

**Files:**
- Modify: `internal/observability/metrics.go:30-33` (buckets), `:61` (observers)
- Modify: `internal/ingress/docker/outcome.go:34-38` (`MetricsObserver`), `:57-111` (`Apply`)
- Modify: `internal/ingress/docker/manifest.go:207-273`
- Test: `internal/observability/metrics_test.go`, `internal/ingress/docker/manifest_flow_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `MetricsObserver` gains `ObserveAssembleDuration(seconds float64)`, `ObserveQueueWait(seconds float64)`, and `ObservePromoteDuration(seconds float64)`. All three are optional-interface-checked exactly like the existing `ObservePushError` (`outcome.go:116-120`), so every existing fake in `*_test.go` keeps compiling without edits.

- [ ] **Step 1: Write the failing test for wide buckets**

```go
// internal/observability/metrics_test.go
func TestScanDurationBucketsCoverGateTimeout(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	// The gate timeout default is 5m; a histogram that cannot express 300s
	// reports every real scan as +Inf and hides the p95 entirely.
	m.ObserveScanDuration(290)

	got := testutil.CollectAndCount(reg, "merlin_scan_duration_seconds")
	if got == 0 {
		t.Fatal("scan duration not collected")
	}
	var found bool
	for _, mf := range mustGather(t, reg) {
		if mf.GetName() != "merlin_scan_duration_seconds" {
			continue
		}
		for _, b := range mf.GetMetric()[0].GetHistogram().GetBucket() {
			if b.GetUpperBound() >= 290 && b.GetCumulativeCount() == 1 {
				found = true
			}
		}
	}
	if !found {
		t.Error("no finite bucket captured a 290s scan; buckets top out too low")
	}
}
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `go test ./internal/observability/ -run TestScanDurationBucketsCoverGateTimeout -v`
Expected: FAIL — `no finite bucket captured a 290s scan`, because `DefBuckets` ends at 10.

- [ ] **Step 3: Replace DefBuckets with explicit buckets spanning the gate timeout**

```go
// internal/observability/metrics.go — in New(), replacing Buckets: prometheus.DefBuckets
// Buckets must span the full gate timeout (default 5m) AND resolve finely around
// the 30s client ResponseHeaderTimeout, which is the number that decides whether
// a push can succeed at all. DefBuckets topped out at 10s: every real scan landed
// in +Inf and p95 was unrecoverable.
Buckets: []float64{1, 2.5, 5, 10, 15, 20, 25, 30, 45, 60, 90, 120, 180, 300, 600},
```

- [ ] **Step 4: Run it to confirm it passes**

Run: `go test ./internal/observability/ -run TestScanDurationBucketsCoverGateTimeout -v`
Expected: PASS

- [ ] **Step 5: Add the two new duration observers**

```go
// internal/observability/metrics.go — add to the Metrics struct
assembleDuration prometheus.Histogram
queueWait        prometheus.Histogram
promoteDuration  prometheus.Histogram
```

```go
// in New(), alongside scanDuration
assembleDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
	Name:    "merlin_assemble_duration_seconds",
	Help:    "Time to assemble the staged image into an OCI layout.",
	Buckets: []float64{0.5, 1, 2.5, 5, 10, 15, 20, 30, 60, 120, 300},
}),
// Queue wait is the time a push spends waiting for one of scan_pool_size slots.
// It is deliberately excluded from scan duration (pool.go:45-48) and so was
// previously invisible — yet with 2 slots against a burst it is expected to be
// the largest term in the blocked window. Buckets must reach the full gate
// timeout: queue wait gets its OWN 5m budget on top of the scan's.
queueWait: prometheus.NewHistogram(prometheus.HistogramOpts{
	Name:    "merlin_gate_queue_wait_seconds",
	Help:    "Time a push waited for a scan slot before its scan began.",
	Buckets: []float64{0.1, 0.5, 1, 2.5, 5, 10, 15, 20, 30, 45, 60, 120, 300, 600},
}),
promoteDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
	Name:    "merlin_promote_duration_seconds",
	Help:    "Time to push the passed image (blobs + manifest) to ACR.",
	Buckets: []float64{0.5, 1, 2.5, 5, 10, 15, 20, 30, 60, 120, 300, 600},
}),
```

```go
// register them
reg.MustRegister(m.pushTotal, m.scanDuration, m.assembleDuration, m.queueWait,
	m.promoteDuration, m.scannerDBAge, m.acrPush)

// observers
func (m *Metrics) ObserveAssembleDuration(seconds float64) { m.assembleDuration.Observe(seconds) }
func (m *Metrics) ObserveQueueWait(seconds float64)        { m.queueWait.Observe(seconds) }
func (m *Metrics) ObservePromoteDuration(seconds float64)  { m.promoteDuration.Observe(seconds) }
```

- [ ] **Step 6: Observe assemble time in the handler**

```go
// internal/ingress/docker/manifest.go — wrap the existing Assemble call (line ~218)
assembleStart := time.Now()
img, err := h.store.Assemble(ctx, mr, scratchDir)
h.observeAssemble(time.Since(assembleStart))
if err != nil {
	http.Error(w, fmt.Sprintf("assemble image: %v", err), http.StatusInternalServerError)
	return
}
```

```go
// internal/ingress/docker/manifest.go — optional-interface helper, mirroring
// Outcome.observePushError so existing metrics fakes keep compiling unchanged.
func (h *Handler) observeAssemble(d time.Duration) {
	if h.outcome == nil || h.outcome.Metrics == nil {
		return
	}
	if m, ok := h.outcome.Metrics.(interface{ ObserveAssembleDuration(float64) }); ok {
		m.ObserveAssembleDuration(d.Seconds())
	}
}
```

- [ ] **Step 6b: Observe queue wait around Acquire**

```go
// internal/ingress/docker/manifest.go — wrap the existing Acquire (line ~250)
waitCtx, cancelWait := context.WithTimeout(ctx, timeout)
waitStart := time.Now()
release, aerr := h.pool.Acquire(waitCtx)
cancelWait()
// Observe on EVERY path, including both failure paths below. The pushes that
// exceed the client's 30s ceiling are exactly the ones that fail here, so
// observing only on success yields survivor bias and makes queue wait look
// healthy precisely when it is the problem.
h.observeQueueWait(time.Since(waitStart))
```

```go
// internal/ingress/docker/manifest.go
func (h *Handler) observeQueueWait(d time.Duration) {
	if h.outcome == nil || h.outcome.Metrics == nil {
		return
	}
	if m, ok := h.outcome.Metrics.(interface{ ObserveQueueWait(float64) }); ok {
		m.ObserveQueueWait(d.Seconds())
	}
}
```

This metric is the **only** evidence for one failure mode. When a client disconnects
at 30s while still queued, `Acquire` returns `ctx.Err()` and `manifest.go:258-261`
returns silently — no response, no audit row, no existing metric. Those pushes are
currently invisible in every data source.

- [ ] **Step 6c: Write the failing test that queue wait is observed on the disconnect path**

```go
// internal/ingress/docker/manifest_flow_test.go
func TestQueueWaitObservedWhenClientDisconnects(t *testing.T) {
	m := &recordingMetrics{}
	// Pool with zero free slots, so Acquire blocks until ctx dies.
	h := newTestHandler(t, withMetrics(m), withFullPool())

	ctx, cancel := context.WithCancel(context.Background())
	req := newManifestPUT(t, "app", "v1").WithContext(ctx)
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	h.ServeHTTP(httptest.NewRecorder(), req)

	if m.queueWaits() != 1 {
		t.Fatalf("queue wait observations = %d, want 1; a push that died queued left no trace", m.queueWaits())
	}
}
```

Run: `go test ./internal/ingress/docker/ -run TestQueueWaitObservedWhenClientDisconnects -v`
Expected: FAIL first (no observation on that path), then PASS after Step 6b.

- [ ] **Step 7: Observe ACR push time in Apply**

```go
// internal/ingress/docker/outcome.go — replace the bare pusher.Push at line ~97
promoteStart := time.Now()
err := pusher.Push(ctx, req.Image.OCIPath, req.Target)
o.observePromote(time.Since(promoteStart))
if err != nil {
	// ... existing 502 branch unchanged
}
```

```go
func (o *Outcome) observePromote(d time.Duration) {
	if o.Metrics == nil {
		return
	}
	if m, ok := o.Metrics.(interface{ ObservePromoteDuration(float64) }); ok {
		m.ObservePromoteDuration(d.Seconds())
	}
}
```

- [ ] **Step 8: Run the full suite with race detection**

Run: `go test -race ./internal/observability/ ./internal/ingress/docker/`
Expected: PASS, no fakes broken (both new methods are optional-interface).

- [ ] **Step 9: Commit**

```bash
git add internal/observability/metrics.go internal/observability/metrics_test.go \
        internal/ingress/docker/manifest.go internal/ingress/docker/outcome.go
git commit -m "feat(metrics): widen scan buckets past 10s, measure assemble and ACR promote

DefBuckets topped out at 10s so every real scan landed in +Inf and p95 was
unrecoverable. scanDur also excluded both Assemble and the ACR push, which are
inside the blocked manifest-PUT window. Adds explicit buckets to 600s with fine
resolution around the 30s client ResponseHeaderTimeout, plus assemble/promote
histograms, so the blocked window can be attributed."
```

---

## Task 2: Read the measurement and pick the variant

**This is a decision gate, not a code change.** Do not start Task 3 before completing it.

- [ ] **Step 1: Query the historical gate duration from the audit store**

`outcome.go:72` already persists exact per-push `DurationMS`, so history exists even though the histogram was useless. The 30-day TTL means the Aug 4 buildah baseline is still present as of 2026-08-11 but expires ~Sep 3.

```sql
SELECT
  quantile(0.50)(duration_ms) / 1000 AS p50_s,
  quantile(0.95)(duration_ms) / 1000 AS p95_s,
  max(duration_ms) / 1000           AS max_s,
  count()                           AS n
FROM merlin.decisions
WHERE ts >= now() - INTERVAL 30 DAY AND infra_error = 0;
```

Record the numbers in this document before proceeding. Two caveats that will otherwise cause the result to be misread:

- The column covers `Gate` **only**. It excludes assemble, excludes the ACR push, and excludes queue wait (`gateStart` is taken after `Acquire`). It is a *lower bound* on the blocked window, not the window.
- **The rows undercount the failures.** A push whose client disconnects at 30s while still queued returns at `manifest.go:258-261` with no audit row at all. A push that disconnects mid-scan does record `infra_error = 1`. So the 37 failures are split between rows that exist and rows that never existed, and `WHERE infra_error = 0` hides the rest. Cross-check against ingress request counts, not against this table alone.

- [ ] **Step 2: Deploy Task 1 and collect one gate-push burst of the new histograms**

One *burst*, not one day: the failure is a tail-of-burst effect and a day of median traffic will not reproduce it. If `ServiceMonitor` is still absent (see `docs/plans/2026-08-11-llm-observability-agent.md` §1.1), scrape `/metrics` directly:

```bash
kubectl exec -n merlin deploy/merlin -- \
  wget -qO- localhost:9090/metrics \
  | grep -E 'merlin_(scan_duration|assemble_duration|gate_queue_wait|promote_duration)_seconds_bucket'
```

- [ ] **Step 3: Apply the decision rule**

The blocked window for a push is:

```
W = t_putmanifest + t_assemble + t_queuewait + t_scan + t_acrpush
```

and it must satisfy `W < 30s` for the **tail push of a burst**, not the median push.
An earlier draft of this plan used `B = p95(assemble) + p95(scan) < 15s` as the rule.
**That rule was wrong** — it omitted `t_queuewait`, which the arithmetic below predicts
is the dominant term.

With `S` slots (fixed at 2) and a burst of `N` images (~37) arriving together, the
k-th push waits roughly `floor((k-1)/S) × t_scan` for a slot, so the last one waits
about `(N/S - 1) × t_scan ≈ 18 × t_scan`. Requiring the tail push to fit in 30s gives:

```
t_scan < 30s / (N/S - 1)  ≈  30/18  ≈  1.6s
```

Grype does not scan a real image in 1.6s. Inverting it, the number of pushes in a
burst that can clear 30s is about `S × (30 / t_scan)` — three pushes at a 20s scan,
one at 60s. That predicts 34–36 of 37 failing on queue wait alone, with assemble and
the ACR push at zero, which matches the observed "all 37 fail".

| Measurement | Ship | Consequence |
|---|---|---|
| `p95(W) < 15s` **for the tail push of a burst**, where `W` is the full sum above | **Variant A** (Tasks 3–5) | Verdict stays in the `docker push` exit code; `docs/specs.md` and `docs/CI.md` stay true; no CI change. |
| otherwise | **Variant B** (Tasks 3–6) | 201 means "staged, not scanned"; CI adds a poll step; contract docs rewritten. |

The gate is 15s, not the client's 30s, deliberately: 30s is the hard failure point, so
shipping against it leaves zero headroom for a slower scanner DB, a larger image, or a
burst one image bigger than the one measured. Half the ceiling is the smallest margin
worth taking.

**Expect Variant B.** The arithmetic above makes Variant A viable only if the burst is
smaller than believed or scans are far faster than the Aug 4 baseline suggests. Run the
measurement anyway — it is cheap, it falsifies the model if the model is wrong, and the
per-phase numbers are needed regardless to size Task 6.

Raising `scanPoolSize` is not an escape: at `memoryLimit 2Gi` per slot against a 10Gi
pod limit already carrying ~5.4Gi of upload budget, matching a 37-push burst needs
~74Gi. Record `t_assemble` and `t_acrpush` separately even so — under Variant B they
set the *worker's* throughput, which determines how long CI's poll step waits.

- [ ] **Step 4: Write the decision into this file and commit**

```bash
git add docs/plans/2026-08-11-async-promote.md
git commit -m "docs(plan): record measured assemble/scan/promote split and variant choice"
```

---

## Task 3: Durable promotion queue

Both variants need the ACR push to survive the handler returning. A bare goroutine is not acceptable: with pod restarts, in-flight promotions vanish and the image is never published while the audit row says nothing. The queue is Valkey-backed because Valkey is already a hard dependency (`staging` uses it for blobs and sessions).

**Files:**
- Create: `internal/promote/queue.go`
- Test: `internal/promote/queue_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:

```go
// Job is one unit of deferred promotion work.
type Job struct {
	PushID string // pre-generated; shared with the report URL and audit row
	// Tenant is the tenant prefix (tenant.Tenant.Prefix) the worker resolves the ACR
	// pusher from. A repo name does not identify a tenant under the multi-ACR config,
	// and the request host the prefix came from is gone by the time the worker runs.
	Tenant     string
	Repo       string
	Ref        string   // tag or sha256:... digest, exactly as the client addressed it
	Target     string   // fully-qualified ACR ref
	OCIPath    string   // local OCI layout produced by Assemble
	ScratchDir string   // parent dir to remove after promotion
	Layers     []string // staged layer digests, for ref-count release
	ConfigDig  string
	Identity   string
	Attempts   uint8
}

type Queue interface {
	Enqueue(ctx context.Context, j Job) error
	Claim(ctx context.Context) (Job, bool, error) // false when empty
	Ack(ctx context.Context, pushID string) error
	Recover(ctx context.Context, olderThan time.Duration) ([]Job, error) // re-queue abandoned claims
}
```

- [ ] **Step 1: Write the failing round-trip test**

```go
// internal/promote/queue_test.go
func TestEnqueueClaimAckRoundTrip(t *testing.T) {
	q := NewQueue(newFakeValkey(), "merlin:promote")
	ctx := context.Background()
	want := Job{PushID: "abc123", Repo: "app", Ref: "v1", Target: "acr.io/app:v1", OCIPath: "/tmp/x/oci"}

	if err := q.Enqueue(ctx, want); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	got, ok, err := q.Claim(ctx)
	if err != nil || !ok {
		t.Fatalf("Claim: ok=%v err=%v", ok, err)
	}
	if got.PushID != want.PushID || got.Target != want.Target {
		t.Errorf("Claim = %+v, want %+v", got, want)
	}
	// A claimed job must NOT be handed to a second worker.
	if _, ok, _ := q.Claim(ctx); ok {
		t.Error("claimed job was handed out twice")
	}
	if err := q.Ack(ctx, want.PushID); err != nil {
		t.Fatalf("Ack: %v", err)
	}
}
```

- [ ] **Step 2: Write the failing crash-recovery test**

This is the test that justifies the whole task — it encodes the OOMKill case.

```go
func TestRecoverRequeuesAbandonedClaim(t *testing.T) {
	q := NewQueue(newFakeValkey(), "merlin:promote")
	ctx := context.Background()
	_ = q.Enqueue(ctx, Job{PushID: "abandoned", Target: "acr.io/app:v1"})

	// Worker claims, then the process dies without Ack.
	if _, ok, _ := q.Claim(ctx); !ok {
		t.Fatal("setup: claim failed")
	}
	if _, ok, _ := q.Claim(ctx); ok {
		t.Fatal("setup: job should be invisible while claimed")
	}

	got, err := q.Recover(ctx, 0) // 0 == reclaim everything currently claimed
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(got) != 1 || got[0].PushID != "abandoned" {
		t.Fatalf("Recover = %+v, want the abandoned job", got)
	}
	if _, ok, _ := q.Claim(ctx); !ok {
		t.Error("recovered job is not claimable again")
	}
}
```

- [ ] **Step 3: Run both to confirm they fail**

Run: `go test ./internal/promote/ -run 'TestEnqueueClaimAckRoundTrip|TestRecoverRequeuesAbandonedClaim' -v`
Expected: FAIL — `undefined: NewQueue`.

- [ ] **Step 4: Implement the queue**

Use a Valkey list for pending plus a hash of claimed jobs stamped with claim time, so `Recover` can find claims older than a threshold. Marshal `Job` as JSON.

```go
// internal/promote/queue.go
package promote

// Enqueue appends the job to the pending list. Jobs are JSON so a schema change
// is backward-readable; an unmarshalable job is dropped to the dead list rather
// than crashing the worker loop.
func (q *valkeyQueue) Enqueue(ctx context.Context, j Job) error {
	b, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("marshal promote job %s: %w", j.PushID, err)
	}
	if err := q.c.RPush(ctx, q.pendingKey(), b); err != nil {
		return fmt.Errorf("enqueue promote job %s: %w", j.PushID, err)
	}
	return nil
}

// Claim moves one job from pending into the claimed list and stamps it with the
// claim time, in a single Lua script. Atomicity is the whole point: a non-atomic
// pop-then-record loses the job entirely if the process dies between the two
// operations — precisely the failure this queue exists to prevent.
const claimScript = `
local job = redis.call('LPOP', KEYS[1])
if not job then return nil end
local decoded = cjson.decode(job)
redis.call('RPUSH', KEYS[2], job)
redis.call('HSET', KEYS[3], decoded['PushID'], ARGV[1])
return job
`

func (q *valkeyQueue) Claim(ctx context.Context) (Job, bool, error) {
	raw, err := q.c.Eval(ctx, claimScript,
		[]string{q.pendingKey(), q.claimedKey(), q.stampKey()},
		q.now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return Job{}, false, fmt.Errorf("claim promote job: %w", err)
	}
	if raw == nil {
		return Job{}, false, nil // queue empty
	}
	b, ok := raw.([]byte)
	if !ok {
		return Job{}, false, fmt.Errorf("claim promote job: unexpected reply type %T", raw)
	}
	var j Job
	if err := json.Unmarshal(b, &j); err != nil {
		// An unmarshalable job would poison the loop forever if re-queued. Park it
		// on the dead list and report empty so the worker makes progress.
		_ = q.c.RPush(ctx, q.deadKey(), b)
		return Job{}, false, fmt.Errorf("claim promote job: corrupt payload parked: %w", err)
	}
	return j, true, nil
}

// Ack removes the job from the claimed list and drops its timestamp, so Recover
// will not resurrect a job that already succeeded.
func (q *valkeyQueue) Ack(ctx context.Context, pushID string) error {
	if err := q.c.HDel(ctx, q.stampKey(), pushID); err != nil {
		return fmt.Errorf("ack promote job %s: %w", pushID, err)
	}
	return nil
}

// Recover re-queues jobs claimed longer ago than olderThan — i.e. claims held by
// a worker that died. A zero olderThan reclaims every outstanding claim, which is
// the correct behaviour at process start: this process holds no claims yet, so any
// claim present belongs to a dead predecessor.
func (q *valkeyQueue) Recover(ctx context.Context, olderThan time.Duration) ([]Job, error) {
	stamps, err := q.c.HGetAll(ctx, q.stampKey())
	if err != nil {
		return nil, fmt.Errorf("recover promote claims: %w", err)
	}
	cutoff := q.now().UTC().Add(-olderThan)
	var out []Job
	for pushID, ts := range stamps {
		claimedAt, perr := time.Parse(time.RFC3339Nano, ts)
		// An unparseable stamp is treated as ancient: better to retry a promotion
		// (idempotent — pushing the same digest twice is a no-op in ACR) than to
		// strand an image unpublished forever.
		if perr == nil && claimedAt.After(cutoff) {
			continue
		}
		j, found, gerr := q.moveClaimedToPending(ctx, pushID)
		if gerr != nil {
			return out, fmt.Errorf("recover promote job %s: %w", pushID, gerr)
		}
		if found {
			out = append(out, j)
		}
	}
	return out, nil
}
```

Note the idempotency assumption made explicit above: re-promoting an already-pushed
digest must be a no-op. Verify this against `internal/acr/push.go` before relying on
it — if `Push` is not idempotent, `Recover` needs a "already in ACR?" check first.

- [ ] **Step 5: Run both to confirm they pass**

Run: `go test -race ./internal/promote/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/promote/queue.go internal/promote/queue_test.go
git commit -m "feat(promote): add Valkey-backed durable promotion queue

Deferred ACR promotion must survive pod restarts: an in-memory queue drops
in-flight pushes on OOMKill, leaving an image unpublished with no audit row and
a CI poller that waits forever. Claim is atomic and stamped so Recover can
re-queue claims abandoned by a dead worker."
```

---

## Task 4: The promotion worker

**Files:**
- Create: `internal/promote/promote.go`, `internal/promote/worker.go`
- Test: `internal/promote/worker_test.go`

**Interfaces:**
- Consumes: `Job`, `Queue` from Task 3.
- Produces:

```go
// Promoter accepts a passed image for deferred publication to ACR.
type Promoter interface {
	Promote(ctx context.Context, j Job) error // enqueue only; returns fast
}

// Worker drains the queue. Run blocks until ctx is canceled.
type Worker struct {
	Queue    Queue
	// Pushers resolves the tenant's ACR pusher from the tenant PREFIX carried on
	// the Job — NOT from the repo. Tenants are keyed by host prefix
	// (internal/tenant/resolver.go:26, PrefixFromHost), and under the multi-ACR
	// config two tenants can host the same repo name, so a repo-keyed lookup would
	// publish to the wrong registry.
	Pushers  func(tenantPrefix string) (acr.Pusher, error)
	Recorder DecisionFinalizer
	Cleanup  func(ctx context.Context, j Job) error
	Metrics  interface{ ObservePromoteDuration(float64) }
	MaxAttempts uint8 // default 3
}

func (w *Worker) Run(ctx context.Context)

// DecisionFinalizer updates the already-recorded decision with the promotion
// outcome. Implemented by the audit package.
type DecisionFinalizer interface {
	FinalizePromotion(ctx context.Context, pushID string, ok bool, errDetail string)
}
```

- [ ] **Step 1: Write the failing happy-path test**

```go
// internal/promote/worker_test.go
func TestWorkerPushesAndCleansUp(t *testing.T) {
	q := NewQueue(newFakeValkey(), "k")
	pusher := &fakePusher{}
	var cleaned bool
	fin := &fakeFinalizer{}
	w := &Worker{
		Queue:    q,
		Pushers:  func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder: fin,
		Cleanup:  func(context.Context, Job) error { cleaned = true; return nil },
	}
	_ = q.Enqueue(context.Background(), Job{PushID: "p1", Target: "acr.io/app:v1", OCIPath: "/tmp/oci"})

	ctx, cancel := context.WithCancel(context.Background())
	go w.Run(ctx)
	waitFor(t, func() bool { return pusher.calls() == 1 && cleaned })
	cancel()

	if !fin.ok("p1") {
		t.Error("promotion success was not recorded on the decision")
	}
}
```

- [ ] **Step 2: Write the failing test that cleanup does NOT run on a retryable failure**

Deleting the OCI layout after a failed push would make the retry impossible.

```go
func TestWorkerKeepsScratchForRetry(t *testing.T) {
	q := NewQueue(newFakeValkey(), "k")
	pusher := &fakePusher{err: errors.New("acr 503")}
	var cleaned bool
	w := &Worker{
		Queue:       q,
		Pushers:     func(string) (acr.Pusher, error) { return pusher, nil },
		Recorder:    &fakeFinalizer{},
		Cleanup:     func(context.Context, Job) error { cleaned = true; return nil },
		MaxAttempts: 3,
	}
	_ = q.Enqueue(context.Background(), Job{PushID: "p1", Target: "acr.io/app:v1"})

	ctx, cancel := context.WithCancel(context.Background())
	go w.Run(ctx)
	waitFor(t, func() bool { return pusher.calls() >= 1 })
	cancel()

	if cleaned {
		t.Error("scratch dir was deleted after a retryable failure; the retry cannot succeed")
	}
}
```

- [ ] **Step 2b: Write the failing tenant-routing test**

The two tests above pass `func(string) (acr.Pusher, error)` and ignore the argument, so
they cannot catch a worker that resolves the pusher by the wrong key. Publishing a
tenant's image to another tenant's registry is the worst failure this package can
produce, so it gets its own test:

```go
// internal/promote/worker_test.go
func TestWorkerResolvesPusherByTenantNotRepo(t *testing.T) {
	// Two tenants hosting the SAME repo name — legal under the multi-ACR config,
	// and indistinguishable if the worker keys the lookup on Repo.
	devops := &fakePusher{}
	prod := &fakePusher{}
	byPrefix := map[string]acr.Pusher{"c3devops": devops, "c3prod": prod}

	q := newMemQueue()
	w := &Worker{
		Queue:    q,
		Pushers:  func(prefix string) (acr.Pusher, error) { return byPrefix[prefix], nil },
		Recorder: &fakeFinalizer{},
		Cleanup:  func(context.Context, Job) error { return nil },
	}
	_ = q.Enqueue(context.Background(), Job{
		PushID: "p1", Tenant: "c3prod", Repo: "c3aiops",
		Target: "c3prod.azurecr.io/c3aiops:v1",
	})

	ctx, cancel := context.WithCancel(context.Background())
	go w.Run(ctx)
	waitFor(t, func() bool { return prod.calls() >= 1 })
	cancel()

	if devops.calls() != 0 {
		t.Fatalf("image published to the wrong tenant's registry: devops got %d pushes", devops.calls())
	}
}
```

- [ ] **Step 3: Run all three to confirm they fail**

Run: `go test ./internal/promote/ -run 'TestWorker' -v`
Expected: FAIL — `undefined: Worker`.

- [ ] **Step 4: Implement the worker**

```go
// internal/promote/worker.go
// Run drains the queue until ctx is canceled. The worker uses its OWN context
// for each job, never a request context: the HTTP handler that enqueued the job
// has already returned, so a request-scoped context would be canceled and every
// promotion would fail with context.Canceled.
func (w *Worker) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		j, ok, err := w.Queue.Claim(ctx)
		if err != nil {
			log.Printf("promote: claim failed: %v", err)
			sleepCtx(ctx, time.Second)
			continue
		}
		if !ok {
			sleepCtx(ctx, 200*time.Millisecond)
			continue
		}
		w.handle(ctx, j)
	}
}

// handle promotes one job. On terminal failure (attempts exhausted) it records
// the failure AND cleans up, because no retry will follow. On retryable failure
// it re-queues and leaves the scratch dir intact — deleting the OCI layout would
// make the retry structurally impossible.
func (w *Worker) handle(ctx context.Context, j Job) {
	pusher, err := w.Pushers(j.Tenant)
	if err != nil {
		w.fail(ctx, j, fmt.Errorf("resolve pusher: %w", err))
		return
	}
	start := time.Now()
	err = pusher.Push(ctx, j.OCIPath, j.Target)
	if w.Metrics != nil {
		w.Metrics.ObservePromoteDuration(time.Since(start).Seconds())
	}
	if err != nil {
		w.fail(ctx, j, fmt.Errorf("acr push: %w", err))
		return
	}
	w.Recorder.FinalizePromotion(ctx, j.PushID, true, "")
	if cerr := w.Cleanup(ctx, j); cerr != nil {
		log.Printf("promote %s: cleanup failed (blobs leaked): %v", j.PushID, cerr)
	}
	_ = w.Queue.Ack(ctx, j.PushID)
}
```

- [ ] **Step 5: Run both to confirm they pass**

Run: `go test -race ./internal/promote/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/promote/
git commit -m "feat(promote): add promotion worker with bounded retry

The worker runs on its own context, never a request context: the handler that
enqueued the job has already returned. Scratch dirs survive retryable failures
so the retry has an OCI layout to push."
```

---

## Task 5: Hand off promotion from the handler (both variants)

This task runs under either variant — it is the whole fix under Variant A, and the
foundation for Task 6 under Variant B. It moves the ACR push off the critical path
while the scan still runs synchronously, so on its own **the verdict stays in the
`docker push` exit code** and the documented contract holds.

Be clear about what it does *not* fix: removing `t_acrpush` from the blocked window
does nothing about `t_queuewait`, which Task 2 predicts is the dominant term. If Task 2
selected Variant B, treat this task as necessary-but-insufficient and expect pushes to
keep timing out until Task 6 lands.

Three lifetime hazards make this more than a code move:

1. `manifest.go:216` does `defer h.store.Cleanup(context.WithoutCancel(ctx), mr, scratchDir)`. Once promotion is deferred, that defer deletes the OCI layout the worker still needs. Cleanup must move into the worker.
2. `Apply` generates the `pushID` internally (`outcome.go:62-67`), but the 201 response needs the report URL *before* promotion finishes. `pushID` must be generated by the caller and injected.
3. The worker must not inherit `r.Context()`.

**Files:**
- Modify: `internal/ingress/docker/outcome.go:57-111`
- Modify: `internal/ingress/docker/manifest.go:207-301`
- Modify: `internal/app/app.go:252-265`
- Test: `internal/ingress/docker/manifest_flow_test.go`

**Interfaces:**
- Consumes: `promote.Promoter`, `promote.Job` (Tasks 3–4). The handler is the last place
  that holds the resolved `*tenant.Tenant`, so it is the only place that can populate
  `Job.Tenant` — the worker has no request host to re-resolve from.
- Produces:
  - `docker.PublishFunc = func(ctx context.Context) error`.
  - `Outcome.Apply(ctx, pushID string, publish PublishFunc, req, res, gateErr, scanDur)` — the `acr.Pusher` parameter is **removed**, replaced by `publish`. Every existing caller must be updated; the compiler enumerates them.
  - `Handler.SetPromoter(promote.Promoter)` and an unexported `Handler.promoter` field.
  - `Handler.pushID() string` — exposes the ID generator the `Outcome` already owns.

- [ ] **Step 1: Write the failing test that the handler responds before ACR is touched**

```go
// internal/ingress/docker/manifest_flow_test.go
func TestManifestRespondsWithoutWaitingForACR(t *testing.T) {
	// A pusher that would blow the 30s client budget if it were on the critical path.
	slow := &blockingPusher{block: make(chan struct{})}
	prom := &fakePromoter{}
	h := newTestHandler(t, withPusher(slow), withPromoter(prom))

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newManifestPUT(t, "app", "v1"))
		done <- rec.Code
	}()

	select {
	case code := <-done:
		if code != http.StatusCreated {
			t.Errorf("status = %d, want 201", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not respond within 5s; ACR push is still on the critical path")
	}
	if slow.calls() != 0 {
		t.Error("handler pushed to ACR synchronously")
	}
	if prom.jobs() != 1 {
		t.Errorf("enqueued %d promotion jobs, want 1", prom.jobs())
	}
	close(slow.block)
}
```

- [ ] **Step 2: Write the failing test that a rejected image is never enqueued**

The security-critical assertion of this whole plan.

```go
func TestRejectedImageIsNeverEnqueued(t *testing.T) {
	prom := &fakePromoter{}
	h := newTestHandler(t, withPromoter(prom), withVerdict(policy.Result{Passed: false}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newManifestPUT(t, "app", "v1"))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if prom.jobs() != 0 {
		t.Fatal("a rejected image was enqueued for ACR promotion")
	}
}
```

- [ ] **Step 3: Run both to confirm they fail**

Run: `go test ./internal/ingress/docker/ -run 'TestManifestRespondsWithoutWaitingForACR|TestRejectedImageIsNeverEnqueued' -v`
Expected: FAIL — `withPromoter` undefined.

- [ ] **Step 4: Replace the `pusher` parameter with an injected publish action**

`Apply` should not know whether publication is synchronous or queued. Replacing the
`acr.Pusher` parameter with a closure keeps the pass/reject/infra rendering in one
place and lets the handler — which is the only scope holding `ref`, `scratchDir`,
and `mr` — decide what publishing means.

```go
// internal/ingress/docker/outcome.go

// PublishFunc publishes the passed image. In the synchronous configuration it
// pushes to ACR inline; with a promotion worker it enqueues durable work and
// returns immediately. Apply treats both identically: an error means the image is
// NOT published and must not be reported as a pass.
type PublishFunc func(ctx context.Context) error

// Apply now takes the pushID from the caller. The handler needs it to build the
// report URL for a 201 returned BEFORE promotion completes, so it can no longer
// be generated inside Apply.
func (o *Outcome) Apply(ctx context.Context, pushID string, publish PublishFunc, req router.GateRequest, res policy.Result, gateErr error, scanDur time.Duration) (Decision, error) {
	reportURL := fmt.Sprintf("%s/%s", o.ReportBaseURL, pushID)
	// ... gateErr and !res.Passed branches unchanged, still using pushID ...

	if err := publish(ctx); err != nil {
		if o.Metrics != nil {
			o.Metrics.ObserveACRPush(false)
		}
		// The scan PASSED but the image is not published. Record as an infra
		// failure, never a policy rejection.
		o.recordDecision(ctx, pushID, req, res, false, durMS, fmt.Errorf("publish: %w", err))
		return Decision{StatusCode: 502, Summary: "passed but publication failed", ReportURL: reportURL, InfraError: true}, fmt.Errorf("publish: %w", err)
	}
	if o.Metrics != nil {
		o.Metrics.ObserveACRPush(true)
	}
	o.recordDecision(ctx, pushID, req, res, true, durMS, nil)
	return Decision{StatusCode: 201, Summary: summary, ReportURL: reportURL}, nil
}
```

- [ ] **Step 4b: Build the publish closure in the handler**

```go
// internal/ingress/docker/manifest.go — immediately before the Apply call.
// Every field the worker's Cleanup needs must be carried on the Job: it releases
// blob ref-counts by ConfigDig+Layers and removes ScratchDir. Omitting any of them
// leaks the staged blobs and the OCI layout on every push.
//
// Ref is how the CLIENT addressed the manifest (tag or sha256:...), not
// Image.Tag — buildx addresses the image manifest by digest, and targetRef
// already depends on that distinction.
publish := func(pctx context.Context) error {
	return t.Pusher.Push(pctx, img.OCIPath, target)
}
if h.promoter != nil {
	job := promote.Job{
		PushID:     pushID,
		Tenant:     t.Prefix,
		Repo:       repo,
		Ref:        ref,
		Target:     target,
		OCIPath:    img.OCIPath,
		ScratchDir: scratchDir,
		Layers:     mr.LayerDigests,
		ConfigDig:  mr.ConfigDigest,
		Identity:   identity.Subject,
	}
	publish = func(pctx context.Context) error {
		if err := h.promoter.Promote(pctx, job); err != nil {
			return fmt.Errorf("enqueue promotion: %w", err)
		}
		promoted = true // the worker now owns scratchDir and the blob refs
		return nil
	}
}

d, applyErr := h.outcome.Apply(ctx, pushID, publish, req, res, gateErr, scanDur)
```

Add the field to the handler in `internal/ingress/docker/handler.go` alongside `gateTimeout`:

```go
promoter promote.Promoter // nil = publish to ACR synchronously
```

```go
// SetPromoter defers ACR publication to a durable queue. Nil keeps the
// synchronous push (hermetic tests, single-binary dev).
func (h *Handler) SetPromoter(p promote.Promoter) { h.promoter = p }
```

- [ ] **Step 5: Move cleanup out of the handler's defer**

```go
// internal/ingress/docker/manifest.go — replace the unconditional defer at line ~216.
// Cleanup ownership follows the OCI layout: when promotion is deferred, the worker
// owns both and the handler must NOT delete them. Only the paths that return
// without enqueueing clean up here.
var promoted bool
defer func() {
	if promoted {
		return // the promotion worker owns the scratch dir and blob refs now
	}
	h.store.Cleanup(context.WithoutCancel(ctx), mr, scratchDir)
}()
```

`promoted` is set by the publish closure in Step 4b, not here — the closure runs only
on the pass path inside `Apply`, and only after `Promote` returned nil. Do **not** also
set it after `Apply` returns: if the enqueue failed, `Apply` renders a 502 and the
handler must still clean up, which a second unconditional assignment would prevent.

- [ ] **Step 6: Generate the pushID in the handler**

`Outcome` already owns the generator (`IDGen`, defaulting to `generatePushID` —
`outcome.go:62-66`). Expose it rather than adding a second source of IDs, or a
test that stubs `IDGen` will silently stop controlling the report URL.

```go
// internal/ingress/docker/handler.go
// pushID generates the ID shared by the report URL and the audit row. It reuses
// the Outcome's IDGen so a test that stubs IDGen still controls both.
func (h *Handler) pushID() string {
	if h.outcome != nil && h.outcome.IDGen != nil {
		return h.outcome.IDGen()
	}
	return generatePushID()
}
```

```go
// internal/ingress/docker/manifest.go — before the gate block, so the ID exists
// for both the publish closure and the report URL.
pushID := h.pushID()
```

Order matters inside `handleManifest`: declare `var promoted bool` and its deferred
cleanup (Step 5) **above** the publish closure from Step 4b, which assigns to it.

- [ ] **Step 7: Run the full docker + promote suites**

Run: `go test -race ./internal/ingress/docker/ ./internal/promote/ ./internal/staging/`
Expected: PASS. Every existing `Apply` caller must be updated for the new parameter — the compiler enumerates them.

- [ ] **Step 8: Wire the worker into app.go and start it**

```go
// internal/app/app.go — after the handler is built (~line 252)
promQueue := promote.NewQueue(valkeyClient, "merlin:promote")
worker := &promote.Worker{
	Queue:   promQueue,
	// Resolve by tenant prefix from the same map that built the resolver
	// (app.go:186 populates tenants[tc.Prefix]); do NOT key on repo.
	Pushers: func(prefix string) (acr.Pusher, error) {
		t, ok := tenants[prefix]
		if !ok {
			return nil, fmt.Errorf("promote: unknown tenant prefix %q", prefix)
		}
		return t.Pusher, nil
	},
	Recorder: auditor,
	Cleanup: func(ctx context.Context, j promote.Job) error {
		return store.Cleanup(ctx, staging.ManifestRef{
			Repo: j.Repo, Ref: j.Ref, ConfigDigest: j.ConfigDig, LayerDigests: j.Layers,
		}, j.ScratchDir)
	},
	Metrics: metrics,
}
// Recover claims abandoned by a previous process before serving traffic, or a
// restart mid-promotion leaves images permanently unpublished.
if jobs, err := promQueue.Recover(ctx, 10*time.Minute); err != nil {
	log.Printf("promote: recovery scan failed: %v", err)
} else if len(jobs) > 0 {
	log.Printf("promote: recovered %d abandoned promotions", len(jobs))
}
go worker.Run(ctx)
```

- [ ] **Step 9: Correct the impossible client-timeout advice in docs/CI.md**

Do this in **both** variants — the guidance is false either way. `docs/CI.md:145-148`
currently reads "Set your CI job / registry client timeout generously (Merlin's
default gate timeout is 5 min)." No such setting exists: `ResponseHeaderTimeout` is
a hardcoded `30 * time.Second` literal in BuildKit's `util/resolver` and again in
moby's classic push transport, exposed by no flag, config key, or env var. Replace
that bullet with:

```markdown
- **Push clients cap the wait at 30 seconds.** Both `docker push` and
  `docker buildx build --push` hardcode a 30s `ResponseHeaderTimeout` that no flag
  or environment variable can raise, so Merlin must answer the manifest PUT within
  it. Merlin scans synchronously and publishes to ACR asynchronously to stay inside
  that budget; `gate_timeout` bounds the scan, not your client's patience. A scan
  that exceeds the budget fails the push as an infra error and is not published.
```

- [ ] **Step 10: Commit**

```bash
git add internal/ingress/docker/ internal/app/app.go docs/CI.md
git commit -m "feat(docker): move ACR promotion off the manifest-PUT critical path

Both push clients hardcode a 30s ResponseHeaderTimeout, but the manifest PUT was
held across assemble + scan + the full ACR push. The scan stays synchronous so
the verdict remains in the push exit code; only promotion is deferred to a
durable queue. Cleanup ownership transfers to the worker on enqueue, since the
handler's defer would otherwise delete the OCI layout out from under it."
```

---

## Task 6: Pending report state and CI poll step (Variant B only)

**Skip this task entirely if Task 2 selected Variant A.**

Under Variant B the scan also moves off the critical path, so a 201 no longer carries a verdict and `GET /reports/<ref>` must distinguish three states, not two. Today an unscanned push is a `404` — indistinguishable from a typo'd reference (`report.go:88-91`), which would make a CI poller either exit early on a real image or hang forever on a misspelled one.

**Files:**
- Modify: `internal/ingress/docker/report.go:39-44`, `:88-91`
- Modify: `docs/CI.md:143-149`, `docs/specs.md:41-55`
- Test: `internal/ingress/docker/report_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `reportEnvelope` gains `Pending bool \`json:"pending,omitempty"\``; a known-but-unscanned reference returns `200` with `{"pending": true}` instead of `404`.

- [ ] **Step 1: Write the failing test for the three-state distinction**

```go
func TestReportDistinguishesPendingFromUnknown(t *testing.T) {
	h := newTestHandler(t, withStagedButUnscanned("app", "v1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newGET(t, "/reports/app:v1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("staged-but-unscanned = %d, want 200 with pending", rec.Code)
	}
	var env reportEnvelope
	mustDecode(t, rec.Body, &env)
	if !env.Pending {
		t.Error("pending not set; a poller cannot tell 'not scanned yet' from 'clean'")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, newGET(t, "/reports/nosuch:v9"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown ref = %d, want 404", rec.Code)
	}
}
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `go test ./internal/ingress/docker/ -run TestReportDistinguishesPendingFromUnknown -v`
Expected: FAIL — `env.Pending` undefined.

- [ ] **Step 3: Add the pending state**

```go
// internal/ingress/docker/report.go
// Pending marks a reference Merlin has accepted but not yet decided. It is
// distinct from a 404 (no such reference) and from an empty findings list (scanned
// and clean) — conflating the three makes a CI poller either exit early on a real
// image or block forever on a typo.
Pending bool `json:"pending,omitempty"`
```

- [ ] **Step 4: Run it to confirm it passes**

Run: `go test ./internal/ingress/docker/ -run TestReportDistinguishesPendingFromUnknown -v`
Expected: PASS

- [ ] **Step 5: Document the CI poll step**

The false client-timeout guidance was already corrected in Task 5 Step 9. What
Variant B adds is that the push no longer carries the verdict, so `docs/CI.md:6-13`
("`docker push` *is* your scan-and-publish step. Its exit code is your gate") and
`docs/specs.md:41-55` become wrong and must be rewritten around a two-step gate:

````markdown
```bash
docker buildx build --push -t "$IMAGE" .   # returns as soon as Merlin accepts

# Merlin decides asynchronously; this step is your gate.

# 120 x 5s = 10 min. Sized from the burst tail, not the median push: with 2 scan
# slots and ~37 images, the last image's verdict lands roughly 18 x t_scan after
# submission. A 5-minute ceiling would time out on the tail of a normal burst.
for i in $(seq 1 120); do
  body=$(curl -fsS -u "$CREDS" "https://$MERLIN_HOST/reports/$REPO@$DIGEST") || { sleep 5; continue; }
  echo "$body" | jq -e '.pending == true' >/dev/null || break
  sleep 5
done
echo "$body" > trivy-report.json
echo "$body" | jq -e '.infra_error != true' >/dev/null || { echo "gate did not complete"; exit 1; }
echo "$body" | jq -e '.findings | length == 0' >/dev/null || { echo "policy reject"; exit 1; }
```

The initial `curl` failures are expected and must be retried, not treated as a pass:
audit writes are buffered (`internal/audit/buffer.go`), so a decision is not
queryable the instant the scan finishes.
````

- [ ] **Step 6: Commit**

```bash
git add internal/ingress/docker/report.go internal/ingress/docker/report_test.go docs/CI.md docs/specs.md
git commit -m "feat(reports): add pending state; document async CI gate

An accepted-but-unscanned reference returned 404, indistinguishable from an
unknown one. Also removes the impossible advice to raise the registry client
timeout: ResponseHeaderTimeout is a hardcoded literal in both BuildKit and moby."
```

---

## Open Questions

1. **Disk headroom.** Variant A keeps every passed image's OCI layout on local disk from 201 until promotion completes. With 37 concurrent PR pushes and multi-hundred-MB images, that is unbounded local disk where there used to be none. Needs a bounded in-flight count (reject with 503 when full) and a disk-usage metric. Not yet designed — this is the largest unresolved risk in the plan.
2. ~~**Does `acr.Pusher` resolve per repo or per tenant?**~~ **Resolved: per tenant prefix.** `staticResolver.ForHost` keys a prefix map built from `PrefixFromHost(host, baseDomain)` (`internal/tenant/resolver.go:26`), and repo is not part of that key — two tenants may hold the same repo against different registries. `Job.Tenant` carries the prefix, `Worker.Pushers` takes a prefix, and `TestWorkerResolvesPusherByTenantNotRepo` (Task 4 Step 2b) locks it in. No further work.
3. **`FinalizePromotion` needs a ClickHouse update path.** The audit `Writer` interface (`internal/audit/audit.go:43`) only writes; decisions are append-only. Updating a row post-hoc may need a second row plus `argMax` at read time instead. Resolve before Task 4.
4. **A push that dies while queued leaves no trace at all.** `manifest.go:258-261`
   returns silently when `Acquire` fails with a context error — no response body, no
   audit row, no metric (until Task 1 Step 6b). That is how a large share of the 37
   failures became invisible. Task 1 adds the metric, but arguably the handler should
   also record an audit row for a client-abandoned push, or the audit store will keep
   under-reporting the exact failure mode this plan exists to fix. Decide whether that
   is in scope here or a separate change.
5. **Interaction with the existing `gate_timeout`.** Under Variant A the 5m `gateTimeout` still governs the synchronous scan, which now must fit in 30s of wall clock. The config default becomes misleading: a scan that takes 4m will always fail the client even though Merlin thinks it succeeded, and will then be promoted to ACR anyway. Consider lowering `gate_timeout` to ~20s so Merlin's own deadline matches the client's, and reporting the timeout as an infra error rather than publishing.

## Deliberately Not In This Plan

- **Per-layer scan caching.** Tempting (37 sibling PRs share base layers) but unsound as stated: OS package databases are cumulative and overwritten across layers, so a package installed in layer 2 and removed in layer 5 must not be reported. Unioning per-layer findings produces false positives. A whole-image verdict cache keyed on the config digest is sound but nearly always misses on PR builds.
- **Raising `scanPoolSize` to absorb the burst.** The direct reading of Task 2's
  arithmetic is "add slots", and it does not work. Each slot carries `memoryLimit: 2Gi`
  against a 10Gi pod limit already budgeting ~5.4Gi for uploads
  (`values.opsadmin.multiacr.yaml:90-104`); matching a 37-image burst needs ~74Gi. The
  pool was deliberately lowered 4 → 2 to stop the OOM kills, so raising it re-opens a
  closed bug. Scan concurrency is a memory problem, not a config problem.
- **Returning 202 instead of 201.** The registry V2 spec gives clients no pending semantics, and buildx treats a non-201 manifest response as a failure.
- **Reverting CI to buildah.** `containers/image` has no `ResponseHeaderTimeout` and would work today, so this is a legitimate escape hatch if the 30s ceiling has to be met before this plan lands. It is a workaround, not a fix: it constrains every future client to one toolchain.
