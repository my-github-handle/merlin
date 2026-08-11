package promote

import (
	"strings"
	"testing"
)

// claimScript and requeueScript are multi-key EVALs spanning the pending list, the
// claimed hash, and the stamp hash. A cluster-enabled Valkey refuses any multi-key
// command whose keys hash to different slots (CROSSSLOT), so without a shared hash
// tag Claim fails on EVERY call — and a Claim that always fails means the worker
// never drains a queue whose clients were already answered 201. The image the gate
// accepted would never reach the registry, silently. The tag makes the slot a
// function of the prefix alone, co-locating every key of one queue.
func TestQueueKeysShareOneHashSlot(t *testing.T) {
	for _, prefix := range []string{"", "merlin:promote:it:7"} {
		q := NewValkeyQueue(nil, prefix).(*valkeyQueue)
		keys := map[string]string{
			"pending": q.pendingKey(),
			"claimed": q.claimedKey(),
			"stamps":  q.stampKey(),
			"dead":    q.deadKey(),
		}
		want := prefix
		if want == "" {
			want = DefaultKeyPrefix
		}
		for role, k := range keys {
			tag, ok := hashTag(k)
			if !ok {
				t.Errorf("prefix %q: %s key %q has no {hash tag}; the cluster routes it by the whole key", prefix, role, k)
				continue
			}
			if tag != want {
				t.Errorf("prefix %q: %s key %q hashes on %q, want %q", prefix, role, k, tag, want)
			}
		}
		// One slot is not one key: the four roles must stay distinct, or a claim
		// would overwrite the pending list it came from.
		seen := make(map[string]string, len(keys))
		for role, k := range keys {
			if prev, dup := seen[k]; dup {
				t.Errorf("prefix %q: roles %s and %s collide on key %q", prefix, prev, role, k)
			}
			seen[k] = role
		}
	}
}

// hashTag returns the substring a Redis Cluster hashes for slot assignment: the
// text inside the first non-empty {...}. Mirrors the server's rule so the test
// asserts the actual routing behaviour rather than a string format.
func hashTag(key string) (string, bool) {
	open := strings.Index(key, "{")
	if open < 0 {
		return "", false
	}
	rest := key[open+1:]
	end := strings.Index(rest, "}")
	if end <= 0 { // no close brace, or "{}" which the server does not treat as a tag
		return "", false
	}
	return rest[:end], true
}
