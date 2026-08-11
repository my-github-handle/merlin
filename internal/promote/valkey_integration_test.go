//go:build integration

package promote

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"
)

// Register the Valkey-backed queue with the conformance suite in queue_test.go, so
// the Lua that makes Claim atomic is held to exactly the same contract as the
// in-memory queue. Run with:
//
//	MERLIN_VALKEY_ADDR=localhost:6379 go test -tags integration -race ./internal/promote/
func init() {
	queueImpls = append(queueImpls, struct {
		name string
		new  func(t *testing.T) Queue
	}{"valkey", newIntegrationQueue})
}

var integrationRun int

// newIntegrationQueue returns a queue on a key prefix unique to this test, and
// deletes those keys afterwards. A shared prefix would let one test's leftover
// pending job be claimed by the next.
func newIntegrationQueue(t *testing.T) Queue {
	t.Helper()
	addr := os.Getenv("MERLIN_VALKEY_ADDR")
	if addr == "" {
		t.Skip("set MERLIN_VALKEY_ADDR to run")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("connect valkey at %s: %v", addr, err)
	}
	integrationRun++
	prefix := fmt.Sprintf("merlin:promote:it:%d", integrationRun)
	t.Cleanup(func() {
		ctx := context.Background()
		for _, role := range []string{"pending", "claimed", "stamps", "dead"} {
			rdb.Del(ctx, queueKey(prefix, role))
		}
		rdb.Close()
	})
	return NewValkeyQueue(rdb, prefix)
}

// TestValkeyClaimParksCorruptPayload pins the poison-pill guard: a payload that is
// not valid job JSON must leave the pending list (so the worker makes progress) and
// land on the dead list (so it is not lost silently).
func TestValkeyClaimParksCorruptPayload(t *testing.T) {
	addr := os.Getenv("MERLIN_VALKEY_ADDR")
	if addr == "" {
		t.Skip("set MERLIN_VALKEY_ADDR to run")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	ctx := context.Background()
	prefix := "merlin:promote:it:corrupt"
	t.Cleanup(func() {
		for _, role := range []string{"pending", "claimed", "stamps", "dead"} {
			rdb.Del(ctx, queueKey(prefix, role))
		}
		rdb.Close()
	})
	// Valid JSON (so the Lua's cjson.decode succeeds) but not a job object.
	if err := rdb.RPush(ctx, queueKey(prefix, "pending"), `{"push_id":"x","layers":"not-a-list"}`).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	q := NewValkeyQueue(rdb, prefix)
	if _, ok, err := q.Claim(ctx); ok || err == nil {
		t.Fatalf("Claim = ok:%v err:%v, want (false, error) for a corrupt payload", ok, err)
	}
	n, err := rdb.LLen(ctx, queueKey(prefix, "dead")).Result()
	if err != nil {
		t.Fatalf("LLEN dead: %v", err)
	}
	if n != 1 {
		t.Errorf("dead list length = %d, want 1 (corrupt payload was lost)", n)
	}
	if left, _ := rdb.LLen(ctx, queueKey(prefix, "pending")).Result(); left != 0 {
		t.Errorf("pending length = %d, want 0 (corrupt payload still poisons the loop)", left)
	}
}
