//go:build integration

package promote

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

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

// itRedis returns a client and a prefix scoped to this test, cleaned up afterwards.
// A shared prefix would let one test's leftover pending job be claimed by the next.
func itRedis(t *testing.T, name string) (*redis.Client, string) {
	t.Helper()
	addr := os.Getenv("MERLIN_VALKEY_ADDR")
	if addr == "" {
		t.Skip("set MERLIN_VALKEY_ADDR to run")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("connect valkey at %s: %v", addr, err)
	}
	prefix := "merlin:promote:it:" + name
	t.Cleanup(func() {
		ctx := context.Background()
		for _, role := range []string{"pending", "claimed", "stamps", "dead"} {
			rdb.Del(ctx, queueKey(prefix, role))
		}
		rdb.Close()
	})
	return rdb, prefix
}

// TestValkeyQueueAtAddrConnects is the other half of
// TestNewValkeyQueueAtAddrFailsFastOnABadAddress: the constructor must actually
// return a usable queue when the address is right, not merely reject bad ones.
func TestValkeyQueueAtAddrConnects(t *testing.T) {
	_, prefix := itRedis(t, "dial") // for key cleanup; the queue below dials its own client
	q, err := NewValkeyQueueAtAddr(os.Getenv("MERLIN_VALKEY_ADDR"), prefix)
	if err != nil {
		t.Fatalf("NewValkeyQueueAtAddr: %v", err)
	}
	ctx := context.Background()
	if err := q.Enqueue(ctx, Job{PushID: "dial-1", Target: "acr.io/app:v1"}); err != nil {
		t.Fatalf("Enqueue through the dialed queue: %v", err)
	}
	if n, err := q.Depth(ctx); err != nil || n != 1 {
		t.Errorf("Depth = (%d, %v), want (1, nil)", n, err)
	}
}

// TestValkeyClaimParksPayloadWithoutPushID pins the second poison-pill case, and it
// is the subtler one: the payload parses as a Job, so nothing downstream would
// complain — but claimScript could not key the claim without a push_id, so the job is
// in NO hash. Ack cannot find it and Recover cannot see it. Promoting it would push
// an image that no one can ever mark done, and it would be re-promoted on every
// sweep; parking it is the only outcome that terminates.
func TestValkeyClaimParksPayloadWithoutPushID(t *testing.T) {
	rdb, prefix := itRedis(t, "nopushid")
	ctx := context.Background()
	if err := rdb.RPush(ctx, queueKey(prefix, "pending"), `{"repo":"app","target":"acr.io/app:v1"}`).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	q := NewValkeyQueue(rdb, prefix)
	_, ok, err := q.Claim(ctx)
	if ok || err == nil {
		t.Fatalf("Claim = ok:%v err:%v, want (false, error) for a payload with no push_id", ok, err)
	}
	if !strings.Contains(err.Error(), "no push_id") {
		t.Errorf("error = %q, want it to name the missing push_id", err)
	}
	if n, _ := rdb.LLen(ctx, queueKey(prefix, "dead")).Result(); n != 1 {
		t.Errorf("dead list length = %d, want 1 (the untrackable job was lost)", n)
	}
	// It must not be tracked as claimed either: a claim no one can ack is the leak
	// the claimed hash's own comment warns about.
	if n, _ := rdb.HLen(ctx, queueKey(prefix, "claimed")).Result(); n != 0 {
		t.Errorf("claimed hash size = %d, want 0", n)
	}
	if left, _ := rdb.LLen(ctx, queueKey(prefix, "pending")).Result(); left != 0 {
		t.Errorf("pending length = %d, want 0 (the payload still poisons the loop)", left)
	}
}

// TestValkeyRecoverClearsStampWithoutPayload pins the half-written-claim case: a
// stamp whose payload is gone (a crash between the two HSETs, or an Ack that cleared
// the payload and failed on the stamp). Without the script's unconditional HDELs the
// sweep would find this stamp forever and never make progress on it.
func TestValkeyRecoverClearsStampWithoutPayload(t *testing.T) {
	rdb, prefix := itRedis(t, "orphanstamp")
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	if err := rdb.HSet(ctx, queueKey(prefix, "stamps"), "ghost", old).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	jobs, err := NewValkeyQueue(rdb, prefix).Recover(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("recovered %d jobs, want 0; there was no payload to promote", len(jobs))
	}
	if n, _ := rdb.HLen(ctx, queueKey(prefix, "stamps")).Result(); n != 0 {
		t.Errorf("stamps remaining = %d, want 0; the sweep would loop on it forever", n)
	}
}

// TestValkeyRecoverReportsCorruptClaimedPayload pins that a claimed payload which is
// not job JSON is surfaced, not skipped. It has already been moved back to pending by
// the script, so silence here would let it cycle between the two lists unnoticed.
func TestValkeyRecoverReportsCorruptClaimedPayload(t *testing.T) {
	rdb, prefix := itRedis(t, "corruptclaim")
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	if err := rdb.HSet(ctx, queueKey(prefix, "claimed"), "bad", "{not json").Err(); err != nil {
		t.Fatalf("seed claimed: %v", err)
	}
	if err := rdb.HSet(ctx, queueKey(prefix, "stamps"), "bad", old).Err(); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}

	_, err := NewValkeyQueue(rdb, prefix).Recover(ctx, time.Minute)
	if err == nil {
		t.Fatal("Recover succeeded on a corrupt claimed payload; it would cycle unnoticed")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error = %q, want it to name the push ID that could not be recovered", err)
	}
}

// TestValkeyRecoverTreatsUnparseableStampAsAncient pins the deliberate bias: a stamp
// that cannot be parsed is recovered rather than left alone. Re-promoting an image is
// idempotent; stranding one unpublished forever is not recoverable at all.
func TestValkeyRecoverTreatsUnparseableStampAsAncient(t *testing.T) {
	rdb, prefix := itRedis(t, "badstamp")
	ctx := context.Background()
	payload, err := json.Marshal(Job{PushID: "warped", Target: "acr.io/app:v1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := rdb.HSet(ctx, queueKey(prefix, "claimed"), "warped", payload).Err(); err != nil {
		t.Fatalf("seed claimed: %v", err)
	}
	// Not RFC3339Nano, so time.Parse fails. A "now"-looking value would be the trap:
	// treating it as fresh would hold the claim until someone noticed by hand.
	if err := rdb.HSet(ctx, queueKey(prefix, "stamps"), "warped", "yesterday-ish").Err(); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}

	jobs, err := NewValkeyQueue(rdb, prefix).Recover(ctx, time.Hour)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(jobs) != 1 || jobs[0].PushID != "warped" {
		t.Fatalf("recovered %+v, want the job with the unparseable stamp", jobs)
	}
	if n, _ := rdb.LLen(ctx, queueKey(prefix, "pending")).Result(); n != 1 {
		t.Errorf("pending length = %d, want 1 (the job was not requeued)", n)
	}
}
