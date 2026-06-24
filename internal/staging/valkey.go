package staging

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type valkeySessionStore struct {
	rdb *redis.Client
}

// NewValkeySessionStore connects to Valkey (Redis-protocol) at addr.
func NewValkeySessionStore(addr string) (SessionStore, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("connect valkey: %w", err)
	}
	return &valkeySessionStore{rdb: rdb}, nil
}

func (v *valkeySessionStore) offsetKey(u string) string   { return "merlin:upload:" + u + ":offset" }
func (v *valkeySessionStore) completeKey(d string) string { return "merlin:blob:" + d + ":complete" }

func (v *valkeySessionStore) Begin(ctx context.Context, uploadID string) error {
	return v.rdb.Set(ctx, v.offsetKey(uploadID), 0, 0).Err()
}

// casScript atomically advances offset from expected to next; returns 1 on success.
var casScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  redis.call("SET", KEYS[1], ARGV[2])
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
func (v *valkeySessionStore) MarkComplete(ctx context.Context, _, digest string) error {
	return v.rdb.Set(ctx, v.completeKey(digest), 1, 0).Err()
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
