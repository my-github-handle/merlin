package grype

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

// ReportStore is the shared store behind the scan cache: a byte KV with an
// expiry. It is deliberately narrow — single-key Get/Set only — because the
// deployed Valkey runs in cluster mode, where a multi-key command spanning hash
// slots is rejected outright.
//
// Neither method may be trusted: a store that is down, slow, or serving garbage
// must cost a scan, never a push. Every error path here falls through to a real
// scan.
type ReportStore interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
}

// ScanCacheObserver counts cache outcomes. observability.Metrics satisfies it.
//
// This is the only direct evidence that reuse is happening: scan duration is
// still recorded on a hit (the gate did run, it just did not exec grype), so a
// falling duration histogram would be an inference. A hit/miss counter is the
// measurement.
type ScanCacheObserver interface {
	ObserveScanCache(hit bool)
}

// DefaultScanCacheMaxDBAge bounds how long a cached report may be reused, in
// terms of the age of the vulnerability DB it was produced with.
//
// 24h is not a guess. Anchore rebuilds the DB daily — across 14 days of
// gate_decisions this cluster saw exactly one scanner_db_version per day, built
// between 06:14Z and 06:40Z, with no overlap between consecutive versions. An
// entry that dies at DBBuilt+24h therefore expires no later than the moment its
// successor exists.
//
// The security argument for reuse rests on this bound. A push that arrives at
// 06:16Z is *already* scanned against a DB that is nearly 24h old, because the
// DB is only as fresh as its last daily rebuild. Reusing a report for up to the
// same 24h window therefore admits no staleness the gate does not already
// tolerate — it does not widen the window, it reuses work inside it.
const DefaultScanCacheMaxDBAge = 24 * time.Hour

// reportCacheVersion is the envelope schema version. Bumping it orphans every
// existing entry, which is the intended way to roll out a change to what is
// cached: old entries stop being readable rather than being misread.
const reportCacheVersion = 1

// maxCachedReportBytes caps a single entry. A scan of a large image can carry
// thousands of findings, and a pathological report should degrade to "not
// cached" rather than push megabytes into Valkey on every miss.
const maxCachedReportBytes = 1 << 20 // 1 MiB

// cachedReport is the stored envelope. StoredAt is not used for freshness — the
// DB build time is what bounds reuse — but it makes a dumped key self-describing
// when someone is working out why an image was or was not re-scanned.
type cachedReport struct {
	Version  int       `json:"version"`
	Report   Report    `json:"report"`
	StoredAt time.Time `json:"stored_at"`
}

// reportCacheKey is the content-addressed key for a manifest digest. The digest
// covers the image bytes, and the entry's own DBBuilt covers the other scan
// input, so these two together fully determine a report.
func reportCacheKey(digest string) string { return "merlin:scan:v1:" + digest }

// WithReportCache reuses a previous scan of the same manifest digest instead of
// re-running grype.
//
// What is cached is the grype *Report*, not the Verdict. That distinction is the
// point: threshold and observe mode are applied to the report on every
// evaluation, so changing either takes effect immediately instead of being
// masked by entries scanned under the old configuration. It also keeps the
// DB-age gauge live, since Evaluate still observes DBBuilt on a hit.
//
// maxDBAge bounds reuse against the vulnerability DB's build time; non-positive
// falls back to DefaultScanCacheMaxDBAge. Passing a nil store disables the cache.
func WithReportCache(s ReportStore, maxDBAge time.Duration) Option {
	return func(p *Policy) {
		p.cache = s
		if maxDBAge <= 0 {
			maxDBAge = DefaultScanCacheMaxDBAge
		}
		p.cacheMaxDBAge = maxDBAge
	}
}

// WithScanCacheObserver counts cache hits and misses. Nil is a no-op.
func WithScanCacheObserver(o ScanCacheObserver) Option {
	return func(p *Policy) { p.cacheObserver = o }
}

// scanOrReuse returns the grype report for a staged image, reusing a cached
// report for the same manifest digest when one is still sound to use.
//
// A miss, an unusable entry and a broken store are all the same thing from here:
// run the scan.
func (p *Policy) scanOrReuse(ctx context.Context, img policy.StagedImage) (Report, error) {
	if rep, ok := p.lookupReport(ctx, img.Digest); ok {
		p.observeCache(true)
		return rep, nil
	}
	p.observeCache(false)
	rep, err := p.runner.Scan(ctx, img.OCIPath)
	if err != nil {
		// Not cached: a failed scan produced no report, and caching failure would
		// turn one bad scan into a stream of them.
		return Report{}, err
	}
	p.storeReport(ctx, img.Digest, rep)
	return rep, nil
}

// clock returns the policy's time source.
func (p *Policy) clock() func() time.Time {
	if p.now != nil {
		return p.now
	}
	return time.Now
}

// lookupReport returns a reusable cached report for this digest, if there is one.
//
// Returns false for every reason a report might not be reusable, and never an
// error: the caller's only recourse is to scan, which is also what it does on a
// plain miss.
func (p *Policy) lookupReport(ctx context.Context, digest string) (Report, bool) {
	if p.cache == nil || digest == "" {
		return Report{}, false
	}
	raw, found, err := p.cache.Get(ctx, reportCacheKey(digest))
	switch {
	case err != nil:
		// Log and scan. A cache that cannot be read is a throughput problem, and
		// must never become a correctness or availability one.
		log.Printf("scan cache: read %s failed, scanning instead: %v", digest, err)
		return Report{}, false
	case !found:
		return Report{}, false
	}
	var entry cachedReport
	if err := json.Unmarshal(raw, &entry); err != nil {
		log.Printf("scan cache: entry for %s is unreadable, scanning instead: %v", digest, err)
		return Report{}, false
	}
	if entry.Version != reportCacheVersion {
		return Report{}, false
	}
	if !p.reportIsFresh(entry.Report) {
		return Report{}, false
	}
	return entry.Report, true
}

// reportIsFresh reports whether a cached report was produced with a
// vulnerability DB recent enough to still stand behind a gate decision.
//
// An unknown build time is never fresh. Merlin cannot tell a DB that grype
// simply did not describe from one that is a year stale, and this is a
// fail-closed gate, so the unknown case costs a scan.
func (p *Policy) reportIsFresh(rep Report) bool {
	if rep.DBBuilt.IsZero() {
		return false
	}
	return p.clock()().UTC().Sub(rep.DBBuilt) < p.cacheMaxDBAge
}

// storeReport caches a freshly produced report. Best effort throughout: a report
// that cannot be stored simply gets re-scanned next time.
func (p *Policy) storeReport(ctx context.Context, digest string, rep Report) {
	if p.cache == nil || digest == "" {
		return
	}
	// Without a build time the entry could never pass reportIsFresh, so writing it
	// would only consume Valkey.
	if rep.DBBuilt.IsZero() {
		return
	}
	ttl := p.entryTTL(rep)
	if ttl <= 0 {
		return
	}
	raw, err := json.Marshal(cachedReport{
		Version:  reportCacheVersion,
		Report:   rep,
		StoredAt: p.clock()().UTC(),
	})
	if err != nil {
		log.Printf("scan cache: could not encode report for %s: %v", digest, err)
		return
	}
	if len(raw) > maxCachedReportBytes {
		log.Printf("scan cache: report for %s is %d bytes, over the %d-byte cap; not caching",
			digest, len(raw), maxCachedReportBytes)
		return
	}
	if err := p.cache.Set(ctx, reportCacheKey(digest), raw, ttl); err != nil {
		log.Printf("scan cache: write %s failed: %v", digest, err)
	}
}

// entryTTL is the time left before this report's DB is due to be superseded.
//
// Expiry is derived from the DB's build time rather than from now, so an entry
// written late in a DB's life gets a correspondingly short life. A fixed TTL
// would let the last entry written before a rebuild outlive the DB it was made
// with.
func (p *Policy) entryTTL(rep Report) time.Duration {
	return rep.DBBuilt.Add(p.cacheMaxDBAge).Sub(p.clock()().UTC())
}

// observeCache records a hit or miss.
func (p *Policy) observeCache(hit bool) {
	if p.cacheObserver != nil {
		p.cacheObserver.ObserveScanCache(hit)
	}
}
