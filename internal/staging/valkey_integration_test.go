//go:build integration

package staging

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestValkeyCASRoundTrip(t *testing.T) {
	addr := os.Getenv("MERLIN_VALKEY_ADDR")
	if addr == "" {
		t.Skip("set MERLIN_VALKEY_ADDR to run")
	}
	ss, err := NewValkeySessionStore(addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = ss.Begin(ctx, "it-u1")
	ok, err := ss.CompareAndSetOffset(ctx, "it-u1", 0, 7)
	if err != nil || !ok {
		t.Fatalf("first CAS: ok=%v err=%v", ok, err)
	}
	if ok, _ := ss.CompareAndSetOffset(ctx, "it-u1", 0, 9); ok {
		t.Error("stale CAS should fail against Valkey")
	}
	_ = ss.Clear(ctx, "it-u1")
}

// TestValkeyKeysExpire pins the leak backstop: every key this store writes must
// carry a TTL. Observed live before the fix: 4851 "merlin:upload:*:offset" keys and
// 149 "merlin:blob:*" keys, all TTL=-1, in a Valkey with maxmemory_policy=noeviction.
// Explicit cleanup cannot cover a SIGKILL (OOM skips defers) or a push abandoned
// before its manifest, so the TTL is the only thing that bounds growth.
func TestValkeyKeysExpire(t *testing.T) {
	addr := os.Getenv("MERLIN_VALKEY_ADDR")
	if addr == "" {
		t.Skip("set MERLIN_VALKEY_ADDR to run")
	}
	ss, err := NewValkeySessionStore(addr)
	if err != nil {
		t.Fatal(err)
	}
	v := ss.(*valkeySessionStore)
	ctx := context.Background()

	const uploadID = "it-ttl-u1"
	const digest = "sha256:it-ttl-d1"
	t.Cleanup(func() {
		_ = ss.Clear(ctx, uploadID)
		v.rdb.Del(ctx, v.completeKey(digest), v.refKey(digest))
	})

	// ttlOf returns the key's remaining TTL. go-redis maps a key with no expiry to
	// -1ns and a missing key to -2ns, so a positive duration means "bounded".
	ttlOf := func(key string) time.Duration {
		d, err := v.rdb.TTL(ctx, key).Result()
		if err != nil {
			t.Fatalf("ttl %s: %v", key, err)
		}
		return d
	}

	if err := ss.Begin(ctx, uploadID); err != nil {
		t.Fatal(err)
	}
	if d := ttlOf(v.offsetKey(uploadID)); d <= 0 {
		t.Errorf("after Begin: offset key TTL = %v, want > 0 (key would leak forever)", d)
	}

	// The CAS must PRESERVE the expiry. A bare SET in the Lua script clears it, so
	// without KEEPTTL the very first uploaded chunk would make the key immortal —
	// the leak would survive the fix in Begin entirely.
	ok, err := ss.CompareAndSetOffset(ctx, uploadID, 0, 512)
	if err != nil || !ok {
		t.Fatalf("cas: ok=%v err=%v", ok, err)
	}
	if d := ttlOf(v.offsetKey(uploadID)); d <= 0 {
		t.Errorf("after CompareAndSetOffset: offset key TTL = %v, want > 0 (CAS dropped the TTL — needs KEEPTTL)", d)
	}

	if err := ss.MarkComplete(ctx, uploadID, digest); err != nil {
		t.Fatal(err)
	}
	if d := ttlOf(v.completeKey(digest)); d <= 0 {
		t.Errorf("after MarkComplete: complete key TTL = %v, want > 0 (nothing ever deletes this key)", d)
	}

	if _, err := ss.IncBlobRef(ctx, digest); err != nil {
		t.Fatal(err)
	}
	if d := ttlOf(v.refKey(digest)); d <= 0 {
		t.Errorf("after IncBlobRef: ref key TTL = %v, want > 0 (INCR creates keys with no expiry)", d)
	}
}

// TestValkeyDecBlobRefMissingCounter pins the real-Valkey behaviour behind the
// leak-not-delete invariant. Plain DECR on a missing key returns -1 AND creates the
// key, which Cleanup's "remaining <= 0" test reads as "safe to delete the bytes" —
// so an expired counter could delete a layer a concurrent push is mid-Assemble on.
// The Lua script must report the absent counter as an error instead.
func TestValkeyDecBlobRefMissingCounter(t *testing.T) {
	addr := os.Getenv("MERLIN_VALKEY_ADDR")
	if addr == "" {
		t.Skip("set MERLIN_VALKEY_ADDR to run")
	}
	ss, err := NewValkeySessionStore(addr)
	if err != nil {
		t.Fatal(err)
	}
	v := ss.(*valkeySessionStore)
	ctx := context.Background()

	const digest = "sha256:it-ref-missing"
	v.rdb.Del(ctx, v.refKey(digest))
	t.Cleanup(func() { v.rdb.Del(ctx, v.refKey(digest)) })

	if _, err := ss.DecBlobRef(ctx, digest); err == nil {
		t.Error("DecBlobRef on absent counter returned nil error; Cleanup would delete a blob whose ref count is unknown")
	}
	// The probe must not have materialized the key (plain DECR would leave it at -1).
	if n, err := v.rdb.Exists(ctx, v.refKey(digest)).Result(); err != nil || n != 0 {
		t.Errorf("absent ref key exists = %d (err=%v), want 0 — DecBlobRef must not create it", n, err)
	}

	// Two references: the first release must report 1 remaining, not authorize deletion.
	for i := 0; i < 2; i++ {
		if _, err := ss.IncBlobRef(ctx, digest); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := ss.DecBlobRef(ctx, digest); err != nil || n != 1 {
		t.Errorf("first release of shared blob = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := ss.DecBlobRef(ctx, digest); err != nil || n != 0 {
		t.Errorf("last release of shared blob = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := v.rdb.Exists(ctx, v.refKey(digest)).Result(); err != nil || n != 0 {
		t.Errorf("ref key exists = %d (err=%v), want 0 — counter must be deleted at zero", n, err)
	}
}
