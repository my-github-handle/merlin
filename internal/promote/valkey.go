package promote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultKeyPrefix namespaces this queue's keys inside the Valkey that
// internal/staging also uses.
const DefaultKeyPrefix = "merlin:promote"

// valkeyQueue is the durable Queue. Its state is four keys, all sharing one hash
// tag so a clustered Valkey routes them to the same slot (see queueKey):
//
//	{<prefix>}:pending  LIST  of job JSON, oldest first
//	{<prefix>}:claimed  HASH  push_id -> job JSON (the exact enqueued bytes)
//	{<prefix>}:stamps   HASH  push_id -> RFC3339Nano claim time
//	{<prefix>}:dead     LIST  of payloads that could not be parsed
//
// Claim keeps the job bytes verbatim rather than re-encoding them in Lua: a
// cjson round trip is not byte-stable (an empty Layers slice comes back as {}
// instead of []), and the payload is what a later schema version has to read.
//
// NOTE on TTLs: internal/staging sets a TTL on every key it writes, because its
// keys are per-push scratch that leaked without one. These keys are deliberately
// immortal — expiring a pending or claimed job would silently discard an image the
// gate already approved and told the client was accepted, which is the one outcome
// worse than a leak. Growth is bounded instead by the worker: every job is either
// acked, recovered, or retired to the dead list after its attempt budget.
type valkeyQueue struct {
	rdb    *redis.Client
	prefix string
	now    func() time.Time
}

// NewValkeyQueue returns a durable Queue backed by rdb. An empty prefix uses
// DefaultKeyPrefix.
func NewValkeyQueue(rdb *redis.Client, prefix string) Queue {
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	return &valkeyQueue{rdb: rdb, prefix: prefix, now: time.Now}
}

// NewValkeyQueueAtAddr dials addr and verifies the connection before returning, so
// a misconfigured address fails at startup rather than on the first promotion.
func NewValkeyQueueAtAddr(addr, prefix string) (Queue, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("connect valkey for promote queue: %w", err)
	}
	return NewValkeyQueue(rdb, prefix), nil
}

// queueKey names one of the queue's keys, wrapping the prefix in a Redis Cluster
// hash tag so all of them land in a single slot.
//
// The tag is not cosmetic. claimScript and requeueScript are multi-key EVALs over
// pending + claimed + stamps, and a cluster-enabled Valkey rejects any multi-key
// command whose keys hash to different slots. Untagged, Claim failed with CROSSSLOT
// on every call, so the worker could never drain a queue whose clients had already
// been answered 201 — the gate accepted images that were then never published, with
// nothing but a worker log line to say so.
//
// Cluster mode is not something Merlin gets to assume away: a single-node Valkey
// with cluster_enabled:1 enforces the rule exactly like a sharded one, so this must
// hold regardless of topology. Tagging on the prefix (not a constant) keeps each
// queue's keys together without forcing two different prefixes into the same slot.
func queueKey(prefix, role string) string { return "{" + prefix + "}:" + role }

func (q *valkeyQueue) pendingKey() string { return queueKey(q.prefix, "pending") }
func (q *valkeyQueue) claimedKey() string { return queueKey(q.prefix, "claimed") }
func (q *valkeyQueue) stampKey() string   { return queueKey(q.prefix, "stamps") }
func (q *valkeyQueue) deadKey() string    { return queueKey(q.prefix, "dead") }

// Enqueue appends the job to the pending list. Jobs are JSON so a schema change
// is backward-readable; an unparseable job is parked on the dead list by Claim
// rather than crashing the worker loop.
func (q *valkeyQueue) Enqueue(ctx context.Context, j Job) error {
	b, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("marshal promote job %s: %w", j.PushID, err)
	}
	if err := q.rdb.RPush(ctx, q.pendingKey(), b).Err(); err != nil {
		return fmt.Errorf("enqueue promote job %s: %w", j.PushID, err)
	}
	return nil
}

// claimScript moves one job from pending into the claimed hash and stamps it with
// the claim time. Atomicity is the whole point: a non-atomic pop-then-record loses
// the job entirely if the process dies between the two operations — precisely the
// failure this queue exists to prevent.
var claimScript = redis.NewScript(`
local job = redis.call('LPOP', KEYS[1])
if not job then return nil end
local id = cjson.decode(job)['push_id']
if not id then return job end
redis.call('HSET', KEYS[2], id, job)
redis.call('HSET', KEYS[3], id, ARGV[1])
return job
`)

func (q *valkeyQueue) Claim(ctx context.Context) (Job, bool, error) {
	// Text() (not Result()) because the reply is the raw job payload; a nil reply
	// (empty pending list) comes back as redis.Nil.
	payload, err := claimScript.Run(ctx, q.rdb,
		[]string{q.pendingKey(), q.claimedKey(), q.stampKey()},
		q.now().UTC().Format(time.RFC3339Nano),
	).Text()
	if errors.Is(err, redis.Nil) {
		return Job{}, false, nil // queue empty
	}
	if err != nil {
		return Job{}, false, fmt.Errorf("claim promote job: %w", err)
	}
	b := []byte(payload)
	var j Job
	if uerr := json.Unmarshal(b, &j); uerr != nil {
		// An unparseable job would poison the loop forever if re-queued. Park it on
		// the dead list and report empty so the worker makes progress.
		_ = q.rdb.RPush(ctx, q.deadKey(), b).Err()
		return Job{}, false, fmt.Errorf("claim promote job: corrupt payload parked: %w", uerr)
	}
	if j.PushID == "" {
		// The Lua could not key the claim without a push_id, so this job is not
		// tracked and Recover cannot find it. Park it rather than promote something
		// no one can ack.
		_ = q.rdb.RPush(ctx, q.deadKey(), b).Err()
		return Job{}, false, fmt.Errorf("claim promote job: payload has no push_id, parked")
	}
	return j, true, nil
}

// Ack retires the claim completely: both the payload and its timestamp go. Dropping
// only the timestamp would leave the payload in the claimed hash forever — an
// unbounded key, which is the leak class internal/staging already had to fix.
func (q *valkeyQueue) Ack(ctx context.Context, pushID string) error {
	if err := q.rdb.HDel(ctx, q.claimedKey(), pushID).Err(); err != nil {
		return fmt.Errorf("ack promote job %s: %w", pushID, err)
	}
	if err := q.rdb.HDel(ctx, q.stampKey(), pushID).Err(); err != nil {
		return fmt.Errorf("ack promote job %s stamp: %w", pushID, err)
	}
	return nil
}

// Depth is the length of the pending list. The claimed hash is deliberately not
// counted: those jobs are draining, and the caller uses this to decide whether to
// admit more work.
func (q *valkeyQueue) Depth(ctx context.Context) (int, error) {
	n, err := q.rdb.LLen(ctx, q.pendingKey()).Result()
	if err != nil {
		return 0, fmt.Errorf("promote queue depth: %w", err)
	}
	return int(n), nil
}

// requeueScript moves one claimed job back to the head of pending and clears its
// claim, atomically. A stamp with no payload is cleared too, so a half-written
// claim cannot make Recover loop on it forever.
var requeueScript = redis.NewScript(`
local job = redis.call('HGET', KEYS[2], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
redis.call('HDEL', KEYS[3], ARGV[1])
if not job then return nil end
redis.call('LPUSH', KEYS[1], job)
return job
`)

func (q *valkeyQueue) Recover(ctx context.Context, olderThan time.Duration) ([]Job, error) {
	stamps, err := q.rdb.HGetAll(ctx, q.stampKey()).Result()
	if err != nil {
		return nil, fmt.Errorf("recover promote claims: %w", err)
	}
	cutoff := q.now().UTC().Add(-olderThan)
	var out []Job
	for pushID, ts := range stamps {
		claimedAt, perr := time.Parse(time.RFC3339Nano, ts)
		// An unparseable stamp is treated as ancient: better to retry a promotion
		// (idempotent) than to strand an image unpublished forever.
		if perr == nil && claimedAt.After(cutoff) {
			continue // still held by a live worker
		}
		payload, rerr := requeueScript.Run(ctx, q.rdb,
			[]string{q.pendingKey(), q.claimedKey(), q.stampKey()}, pushID).Text()
		if errors.Is(rerr, redis.Nil) {
			continue // stamp without a payload; the script cleared it
		}
		if rerr != nil {
			return out, fmt.Errorf("recover promote job %s: %w", pushID, rerr)
		}
		var j Job
		if uerr := json.Unmarshal([]byte(payload), &j); uerr != nil {
			return out, fmt.Errorf("recover promote job %s: unmarshal: %w", pushID, uerr)
		}
		out = append(out, j)
	}
	return out, nil
}
