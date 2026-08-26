package grype

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

// countingRunner records how many times a scan actually ran. Every test in this
// file is ultimately an assertion about that count: the cache exists to make it
// stop growing.
type countingRunner struct {
	mu     sync.Mutex
	calls  int
	report Report
	err    error
}

func (c *countingRunner) Scan(_ context.Context, _ string) (Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.report, c.err
}

func (c *countingRunner) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// fakeStore is an in-memory ReportStore with injectable failures.
type fakeStore struct {
	mu       sync.Mutex
	data     map[string][]byte
	ttls     map[string]time.Duration
	getErr   error
	setErr   error
	setCalls int
}

func newFakeStore() *fakeStore {
	return &fakeStore{data: map[string][]byte{}, ttls: map[string]time.Duration{}}
}

func (f *fakeStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	v, ok := f.data[key]
	return v, ok, nil
}

func (f *fakeStore) Set(_ context.Context, key string, val []byte, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	if f.setErr != nil {
		return f.setErr
	}
	f.data[key] = val
	f.ttls[key] = ttl
	return nil
}

func (f *fakeStore) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.data)
}

func (f *fakeStore) sets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setCalls
}

// recordingCacheObserver captures hit/miss outcomes.
type recordingCacheObserver struct {
	mu     sync.Mutex
	hits   int
	misses int
}

func (r *recordingCacheObserver) ObserveScanCache(hit bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if hit {
		r.hits++
	} else {
		r.misses++
	}
}

func (r *recordingCacheObserver) totals() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits, r.misses
}

// fixed clock helpers. The DB in this cluster is rebuilt daily, so "built" is
// always expressed relative to the moment the test pretends to be running.
var testNow = time.Date(2026, 8, 25, 18, 0, 0, 0, time.UTC)

func at(now time.Time) Option { return withClock(func() time.Time { return now }) }

// freshReport is a report whose DB was built recently enough to reuse.
func freshReport(findings ...policy.Finding) Report {
	return Report{
		DBVersion: "schema v6.1.9 built 2026-08-25T06:17:15Z",
		DBBuilt:   testNow.Add(-12 * time.Hour),
		Findings:  findings,
	}
}

const testDigest = "sha256:aaaa"

func stagedWithDigest() policy.StagedImage {
	return policy.StagedImage{OCIPath: "/oci", Digest: testDigest}
}

// --- the core behaviour: the second push of an identical digest does not scan ---

func TestCacheHitSkipsTheScan(t *testing.T) {
	r := &countingRunner{report: freshReport(policy.Finding{
		CVE: "CVE-1", Severity: "High", Pkg: "zlib", Version: "1.2",
	})}
	store := newFakeStore()
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	first, err := p.Evaluate(context.Background(), stagedWithDigest())
	if err != nil {
		t.Fatalf("first evaluate: %v", err)
	}
	second, err := p.Evaluate(context.Background(), stagedWithDigest())
	if err != nil {
		t.Fatalf("second evaluate: %v", err)
	}

	if got := r.count(); got != 1 {
		t.Errorf("scan ran %d times, want 1 (second push should reuse the cached report)", got)
	}
	if first.Passed != second.Passed || len(first.Findings) != len(second.Findings) {
		t.Errorf("reused verdict differs: first=%+v second=%+v", first, second)
	}
	if second.ScannerDBVersion != first.ScannerDBVersion {
		t.Errorf("reused verdict lost the DB version: %q vs %q",
			second.ScannerDBVersion, first.ScannerDBVersion)
	}
	if len(second.Findings) != 1 || second.Findings[0].CVE != "CVE-1" {
		t.Errorf("findings must survive the round trip, got %+v", second.Findings)
	}
}

func TestCacheMissStoresTheReport(t *testing.T) {
	r := &countingRunner{report: freshReport()}
	store := newFakeStore()
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if store.len() != 1 {
		t.Fatalf("expected 1 cached entry, got %d", store.len())
	}
	if _, ok := store.data[reportCacheKey(testDigest)]; !ok {
		t.Errorf("entry not stored under the digest key; keys=%v", store.data)
	}
}

// --- freshness: a cached report may never outlive the vulnerability DB ---

func TestCacheEntryRejectedWhenDBIsTooOld(t *testing.T) {
	// Stored under a DB built 25h before "now": a newer DB is expected daily, so
	// reusing this would gate the image on a superseded vulnerability set.
	stale := freshReport()
	stale.DBBuilt = testNow.Add(-25 * time.Hour)

	store := newFakeStore()
	seed(t, store, testDigest, stale, testNow.Add(-25*time.Hour))

	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Errorf("a report older than the DB rebuild period must be re-scanned, scans=%d", got)
	}
}

func TestCacheEntryRejectedWhenDBBuiltIsUnknown(t *testing.T) {
	// Zero DBBuilt means grype reported no parseable build time, so freshness
	// cannot be established at all. Fail safe: scan.
	unknown := freshReport()
	unknown.DBBuilt = time.Time{}

	store := newFakeStore()
	seed(t, store, testDigest, unknown, testNow)

	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Errorf("a report with an unknown DB build time must be re-scanned, scans=%d", got)
	}
}

func TestCacheEntryAtExactlyTheBoundaryIsRejected(t *testing.T) {
	// Boundary is exclusive: at exactly maxDBAge the next DB is already due.
	boundary := freshReport()
	boundary.DBBuilt = testNow.Add(-24 * time.Hour)

	store := newFakeStore()
	seed(t, store, testDigest, boundary, testNow.Add(-24*time.Hour))

	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Errorf("entry exactly at the DB boundary must be re-scanned, scans=%d", got)
	}
}

// --- the cache stores the REPORT, not the verdict: config still governs ---

func TestCachedReportStillObeysCurrentThreshold(t *testing.T) {
	// One replica scanned and cached; a replica configured with a STRICTER
	// threshold must reject the same cached report. Caching the verdict instead of
	// the report would silently keep the old threshold in force.
	high := freshReport(policy.Finding{CVE: "CVE-9", Severity: "High", Pkg: "p", Version: "1"})
	store := newFakeStore()
	seed(t, store, testDigest, high, testNow)

	lax := New(&countingRunner{report: high}, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))
	strict := New(&countingRunner{report: high}, "HIGH", WithReportCache(store, 24*time.Hour), at(testNow))

	laxV, err := lax.Evaluate(context.Background(), stagedWithDigest())
	if err != nil {
		t.Fatalf("lax: %v", err)
	}
	strictV, err := strict.Evaluate(context.Background(), stagedWithDigest())
	if err != nil {
		t.Fatalf("strict: %v", err)
	}
	if !laxV.Passed {
		t.Error("High finding should pass a CRITICAL threshold")
	}
	if strictV.Passed {
		t.Error("High finding must fail a HIGH threshold even when the report came from cache")
	}
}

func TestCachedReportStillObeysObserveMode(t *testing.T) {
	crit := freshReport(policy.Finding{CVE: "CVE-8", Severity: "Critical", Pkg: "p", Version: "1"})
	store := newFakeStore()
	seed(t, store, testDigest, crit, testNow)

	p := New(&countingRunner{report: crit}, "CRITICAL",
		Observe(), WithReportCache(store, 24*time.Hour), at(testNow))

	v, err := p.Evaluate(context.Background(), stagedWithDigest())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !v.Passed {
		t.Error("observe mode must still pass on a cached report")
	}
	if len(v.Reasons) != 1 || !hasPrefix(v.Reasons[0], unenforcedPrefix) {
		t.Errorf("observe mode must still mark reasons unenforced, got %v", v.Reasons)
	}
}

// --- a cache hit must not blind the DB-age gauge ---

func TestCacheHitStillObservesDBAge(t *testing.T) {
	rep := freshReport()
	store := newFakeStore()
	seed(t, store, testDigest, rep, testNow)

	sink := &spyDBAge{}
	p := New(&countingRunner{report: rep}, "CRITICAL",
		WithReportCache(store, 24*time.Hour), WithDBAgeObserver(sink), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	// DBBuilt is 12h before now, so the gauge should read half a day.
	if len(sink.days) != 1 {
		t.Fatalf("cache hit must still report DB age, got %v", sink.days)
	}
	if got := sink.days[0]; got < 0.49 || got > 0.51 {
		t.Errorf("DB age = %v days, want ~0.5", got)
	}
}

// --- a cache must never be able to fail a push ---

func TestStoreGetErrorFallsBackToScan(t *testing.T) {
	store := newFakeStore()
	store.getErr = errors.New("valkey down")
	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	v, err := p.Evaluate(context.Background(), stagedWithDigest())
	if err != nil {
		t.Fatalf("a cache read failure must not fail the push: %v", err)
	}
	if !v.Passed {
		t.Error("verdict should come from the real scan")
	}
	if got := r.count(); got != 1 {
		t.Errorf("expected fallback scan, scans=%d", got)
	}
}

func TestStoreSetErrorDoesNotFailPush(t *testing.T) {
	store := newFakeStore()
	store.setErr = errors.New("valkey read-only")
	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("a cache write failure must not fail the push: %v", err)
	}
}

func TestCorruptCacheEntryFallsBackToScan(t *testing.T) {
	store := newFakeStore()
	store.data[reportCacheKey(testDigest)] = []byte("{not json")
	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("a corrupt entry must not fail the push: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Errorf("expected fallback scan on corrupt entry, scans=%d", got)
	}
}

func TestFailedScanIsNotCached(t *testing.T) {
	store := newFakeStore()
	r := &countingRunner{err: errors.New("signal: killed")}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err == nil {
		t.Fatal("expected the scan error to propagate")
	}
	if store.sets() != 0 {
		t.Errorf("a failed scan must never be cached, sets=%d", store.sets())
	}
}

// --- keying preconditions ---

func TestCacheSkippedWhenDigestIsEmpty(t *testing.T) {
	// Without a digest there is no content-addressed key, so reuse would be
	// unsound. Scan every time and store nothing.
	store := newFakeStore()
	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	img := policy.StagedImage{OCIPath: "/oci"} // no Digest
	for i := 0; i < 2; i++ {
		if _, err := p.Evaluate(context.Background(), img); err != nil {
			t.Fatalf("evaluate %d: %v", i, err)
		}
	}
	if got := r.count(); got != 2 {
		t.Errorf("without a digest every push must scan, scans=%d want 2", got)
	}
	if store.sets() != 0 {
		t.Errorf("nothing should be stored without a digest, sets=%d", store.sets())
	}
}

func TestNoCacheConfiguredScansEveryTime(t *testing.T) {
	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", at(testNow))
	for i := 0; i < 3; i++ {
		if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
			t.Fatalf("evaluate %d: %v", i, err)
		}
	}
	if got := r.count(); got != 3 {
		t.Errorf("with no cache configured every push scans, scans=%d want 3", got)
	}
}

func TestDifferentDigestsDoNotShareAnEntry(t *testing.T) {
	store := newFakeStore()
	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	for _, d := range []string{"sha256:aaa", "sha256:bbb"} {
		if _, err := p.Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci", Digest: d}); err != nil {
			t.Fatalf("digest %s: %v", d, err)
		}
	}
	if got := r.count(); got != 2 {
		t.Errorf("distinct digests must each scan, scans=%d want 2", got)
	}
	if store.len() != 2 {
		t.Errorf("expected 2 entries, got %d", store.len())
	}
}

// --- TTL and observability ---

func TestEntryTTLIsBoundedByTheDBRebuildPeriod(t *testing.T) {
	store := newFakeStore()
	r := &countingRunner{report: freshReport()} // DB built 12h ago
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	ttl := store.ttls[reportCacheKey(testDigest)]
	// The DB is 12h old and entries die at DBBuilt+24h, so ~12h of life remain.
	if ttl <= 0 || ttl > 12*time.Hour {
		t.Errorf("ttl %v should be positive and no more than the 12h left of this DB's life", ttl)
	}
}

func TestScanCacheObserverSeesHitsAndMisses(t *testing.T) {
	store := newFakeStore()
	obs := &recordingCacheObserver{}
	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour),
		WithScanCacheObserver(obs), at(testNow))

	for i := 0; i < 3; i++ {
		if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
			t.Fatalf("evaluate %d: %v", i, err)
		}
	}
	hits, misses := obs.totals()
	if misses != 1 || hits != 2 {
		t.Errorf("want 1 miss + 2 hits, got %d miss %d hits", misses, hits)
	}
}

func TestDefaultMaxDBAgeAppliesWhenUnset(t *testing.T) {
	// A non-positive period must fall back to the default rather than disabling
	// freshness (0 would make every entry instantly stale, silently killing reuse).
	store := newFakeStore()
	seed(t, store, testDigest, freshReport(), testNow)
	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 0), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := r.count(); got != 0 {
		t.Errorf("a 12h-old DB should still be reusable under the default period, scans=%d", got)
	}
}

// --- what must never be written ---

func TestReportWithUnknownDBBuiltIsNotCached(t *testing.T) {
	// Such an entry could never pass the freshness check on read, so storing it
	// would only consume Valkey.
	rep := freshReport()
	rep.DBBuilt = time.Time{}
	store := newFakeStore()
	p := New(&countingRunner{report: rep}, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if store.sets() != 0 {
		t.Errorf("a report with no DB build time must not be cached, sets=%d", store.sets())
	}
}

func TestReportFromAnAlreadyStaleDBIsNotCached(t *testing.T) {
	// The scanner returned a report from a DB older than the reuse window, so the
	// entry would be born expired.
	rep := freshReport()
	rep.DBBuilt = testNow.Add(-30 * time.Hour)
	store := newFakeStore()
	p := New(&countingRunner{report: rep}, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if store.sets() != 0 {
		t.Errorf("an already-stale report must not be cached, sets=%d", store.sets())
	}
}

func TestOversizedReportIsNotCached(t *testing.T) {
	// A pathological finding count should degrade to "not cached", not push
	// megabytes into Valkey on every miss.
	big := freshReport()
	for i := 0; i < 40000; i++ {
		big.Findings = append(big.Findings, policy.Finding{
			CVE:          "CVE-2026-00000",
			Severity:     "Negligible",
			Pkg:          "some-package-with-a-longish-name",
			Version:      "1.2.3-r4",
			FixedVersion: "1.2.4-r0",
		})
	}
	store := newFakeStore()
	p := New(&countingRunner{report: big}, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))

	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if store.len() != 0 {
		t.Errorf("an oversized report must not be cached, entries=%d", store.len())
	}
}

func TestStaleEntryVersionIsIgnored(t *testing.T) {
	// An envelope from an older schema must be re-scanned, never misread.
	b, err := json.Marshal(cachedReport{Version: reportCacheVersion + 1, Report: freshReport(), StoredAt: testNow})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	store := newFakeStore()
	store.data[reportCacheKey(testDigest)] = b

	r := &countingRunner{report: freshReport()}
	p := New(r, "CRITICAL", WithReportCache(store, 24*time.Hour), at(testNow))
	if _, err := p.Evaluate(context.Background(), stagedWithDigest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Errorf("an entry from another schema version must be re-scanned, scans=%d", got)
	}
}

// seed writes a cache entry directly, standing in for another replica having
// scanned this digest earlier.
func seed(t *testing.T, s *fakeStore, digest string, rep Report, storedAt time.Time) {
	t.Helper()
	b, err := json.Marshal(cachedReport{Version: reportCacheVersion, Report: rep, StoredAt: storedAt})
	if err != nil {
		t.Fatalf("seed marshal: %v", err)
	}
	s.data[reportCacheKey(digest)] = b
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
