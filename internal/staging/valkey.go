package staging

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultSessionTTL bounds how long per-push staging state survives in Valkey.
//
// Every key this store writes is derived from one in-flight push, so none of it is
// meaningful once that push ends. The explicit cleanup paths (Clear / Cleanup) are
// the primary reclaim; this TTL is the backstop for the cases cleanup cannot cover
// — a SIGKILL (OOM) skips deferred cleanup entirely, and an abandoned push that
// never sends its manifest has no completion event to hook. Without it, keys
// accumulate forever: Valkey here runs maxmemory_policy=noeviction, so unbounded
// growth eventually fails writes rather than evicting.
//
// The value must exceed the longest plausible push (large multi-GB images through
// a slow client, plus the gate's scan budget) or a still-active upload could lose
// its offset mid-push. 24h is far above the observed worst case (~2.5m gates).
const DefaultSessionTTL = 24 * time.Hour

type valkeySessionStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewValkeySessionStore connects to Valkey (Redis-protocol) at addr. Session keys
// expire after DefaultSessionTTL; see that constant for why the backstop exists.
func NewValkeySessionStore(addr string) (SessionStore, error) {
	return NewValkeySessionStoreWithTTL(addr, DefaultSessionTTL)
}

// NewValkeySessionStoreWithTTL is NewValkeySessionStore with an operator-configured
// key lifetime. A non-positive ttl falls back to DefaultSessionTTL rather than
// writing immortal keys — disabling the backstop is never the intent, and an
// unbounded key space is what broke production.
func NewValkeySessionStoreWithTTL(addr string, ttl time.Duration) (SessionStore, error) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("connect valkey: %w", err)
	}
	return &valkeySessionStore{rdb: rdb, ttl: ttl}, nil
}

func (v *valkeySessionStore) offsetKey(u string) string   { return "merlin:upload:" + u + ":offset" }
func (v *valkeySessionStore) completeKey(d string) string { return "merlin:blob:" + d + ":complete" }

func (v *valkeySessionStore) Begin(ctx context.Context, uploadID string) error {
	return v.rdb.Set(ctx, v.offsetKey(uploadID), 0, v.ttl).Err()
}

// casScript atomically advances offset from expected to next; returns 1 on success.
// KEEPTTL is required: a plain SET clears the key's expiry, so advancing the offset
// would silently turn a TTL'd session key into an immortal one — reintroducing the
// leak on the first PATCH of every upload.
var casScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  redis.call("SET", KEYS[1], ARGV[2], "KEEPTTL")
  return 1
end
return 0
`)

func (v *valkeySessionStore) CompareAndSetOffset(ctx context.Context, uploadID string, expected, next int64) (bool, error) {
	res, err := casScript.Run(ctx, v.rdb,
		[]string{v.offsetKey(uploadID)},
		fmt.Sprintf("%d", expected), fmt.Sprintf("%d", next)).Int()
	if err != nil {
		return false, fmt.Errorf("valkey cas: %w", err)
	}
	return res == 1, nil
}

// MarkComplete flags a blob as complete. The completion flag is keyed by digest
// and lives in a different store from the blob bytes; CompleteBlob's
// Put-then-MarkComplete ordering upholds the invariant. AllComplete checks the
// flag, not the bytes — Assemble fails closed if a flagged blob is absent.
// TODO(hardening): cross-store reconciliation for drift detection.
//
// The flag expires after v.ttl. Nothing ever deletes it explicitly — it is keyed by
// digest, not by upload, so no single push's completion can retire it — which made
// it an unbounded second leak. Expiry is safe because the flag only has to outlive
// the push that set it: a client whose blob flag has aged out re-uploads the blob
// (the Docker client already handles a HEAD miss), it does not see a corrupt image.
func (v *valkeySessionStore) MarkComplete(ctx context.Context, _, digest string) error {
	return v.rdb.Set(ctx, v.completeKey(digest), 1, v.ttl).Err()
}

// AllComplete checks whether all digests are flagged as complete. See MarkComplete
// for invariant notes.
func (v *valkeySessionStore) AllComplete(ctx context.Context, digests []string) (bool, error) {
	for _, d := range digests {
		n, err := v.rdb.Exists(ctx, v.completeKey(d)).Result()
		if err != nil {
			return false, fmt.Errorf("valkey exists: %w", err)
		}
		if n == 0 {
			return false, nil
		}
	}
	return true, nil
}

func (v *valkeySessionStore) Clear(ctx context.Context, uploadID string) error {
	return v.rdb.Del(ctx, v.offsetKey(uploadID)).Err()
}

func (v *valkeySessionStore) refKey(d string) string { return "merlin:blob:" + d + ":refs" }

// IncBlobRef atomically increments the reference count for a content digest.
//
// INCR on a missing key creates it with no expiry, so a push that never reaches
// Cleanup (OOM, abandoned before the manifest) strands the counter forever. Bound it
// on every increment: each new referencing push pushes the expiry out, so the
// counter always outlives the pushes it is counting. Best-effort — losing the
// expiry only reinstates the leak for this key, and failing the push would be worse.
func (v *valkeySessionStore) IncBlobRef(ctx context.Context, digest string) (int64, error) {
	n, err := v.rdb.Incr(ctx, v.refKey(digest)).Result()
	if err != nil {
		return 0, fmt.Errorf("valkey incr ref: %w", err)
	}
	_ = v.rdb.Expire(ctx, v.refKey(digest), v.ttl).Err()
	return n, nil
}

// decrScript decrements an existing counter and deletes it at zero, atomically.
// It returns -1 when the key does NOT exist, distinguishing "no references left"
// (0) from "reference count unknown" — DECR alone conflates them, since DECR on a
// missing key also yields -1 while creating the key.
var decrScript = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 then
  return -1
end
local n = redis.call("DECR", KEYS[1])
if n <= 0 then
  redis.call("DEL", KEYS[1])
  return 0
end
return n
`)

// DecBlobRef atomically decrements the reference count and deletes the counter key
// when it reaches zero. The caller deletes the blob bytes only at zero, so a
// finished push never removes a blob a concurrent push still references.
//
// A MISSING counter is an error, not zero. Cleanup leaks the blob on error but
// deletes it at zero, and an absent key means the count is unknown — it may have
// expired (the key is TTL'd) while a concurrent push still holds a reference. Per
// the invariant in Cleanup, an unknown count must leak the blob rather than risk
// deleting a layer another push is mid-Assemble on.
func (v *valkeySessionStore) DecBlobRef(ctx context.Context, digest string) (int64, error) {
	n, err := decrScript.Run(ctx, v.rdb, []string{v.refKey(digest)}).Int64()
	if err != nil {
		return 0, fmt.Errorf("valkey decr ref: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("valkey decr ref %s: reference count missing (expired or never set)", digest)
	}
	return n, nil
}
