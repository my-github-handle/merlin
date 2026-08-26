//go:build integration

package scancache

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Round trips against a live Valkey. Run with:
//
//	MERLIN_VALKEY_ADDR=localhost:6379 go test -tags integration -race ./internal/scancache/
//
// The offline tests cover the failure branches; these cover the two things only a
// real server can show: that a miss is a miss rather than an error, and that the
// TTL is actually applied.
func liveStore(t *testing.T) (*ValkeyStore, string) {
	t.Helper()
	addr := os.Getenv("MERLIN_VALKEY_ADDR")
	if addr == "" {
		t.Skip("set MERLIN_VALKEY_ADDR to run scan-cache integration tests")
	}
	s, err := NewValkeyStoreAtAddr(addr, 0)
	if err != nil {
		t.Fatalf("connect %s: %v", addr, err)
	}
	// Unique key per test so parallel runs and reruns cannot collide.
	key := fmt.Sprintf("merlin:scan:test:%s:%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() {
		_ = s.rdb.Del(context.Background(), key).Err()
		_ = s.rdb.Close()
	})
	return s, key
}

func TestLiveRoundTrip(t *testing.T) {
	s, key := liveStore(t)
	ctx := context.Background()

	want := []byte(`{"version":1,"report":{"DBVersion":"schema v6.1.9"}}`)
	if err := s.Set(ctx, key, want, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, found, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("entry written but not found")
	}
	if string(got) != string(want) {
		t.Errorf("round trip mangled the value:\n got %s\nwant %s", got, want)
	}
}

func TestLiveMissIsNotAnError(t *testing.T) {
	// redis.Nil must become a clean miss. Reported as an error it would be logged
	// as a cache fault on every first push of every image.
	s, key := liveStore(t)
	got, found, err := s.Get(context.Background(), key+":absent")
	if err != nil {
		t.Fatalf("a miss must not be an error, got %v", err)
	}
	if found {
		t.Error("found must be false for an absent key")
	}
	if got != nil {
		t.Errorf("value must be nil on a miss, got %q", got)
	}
}

func TestLiveTTLIsApplied(t *testing.T) {
	s, key := liveStore(t)
	ctx := context.Background()
	if err := s.Set(ctx, key, []byte("x"), 90*time.Second); err != nil {
		t.Fatalf("Set: %v", err)
	}
	ttl, err := s.rdb.TTL(ctx, key).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	// An entry with no expiry would report -1: a scan cache that never forgets is
	// how a superseded vulnerability DB stays in force.
	if ttl <= 0 || ttl > 90*time.Second {
		t.Errorf("TTL = %v, want a positive value no greater than 90s", ttl)
	}
}

func TestLiveExpiredEntryIsAMiss(t *testing.T) {
	s, key := liveStore(t)
	ctx := context.Background()
	if err := s.Set(ctx, key, []byte("x"), 50*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if _, found, err := s.Get(ctx, key); err != nil || found {
		t.Errorf("expired entry should be a clean miss, got found=%v err=%v", found, err)
	}
}

func TestLiveSingleKeyOpsWorkInClusterMode(t *testing.T) {
	// The deployed Valkey runs cluster_enabled:1, where a multi-key command
	// spanning hash slots is rejected CROSSSLOT. This store only ever issues
	// single-key GET/SET, so no hash tag is needed — but assert it against
	// whatever server is configured rather than trusting the reasoning.
	s, _ := liveStore(t)
	ctx := context.Background()
	keys := []string{
		"merlin:scan:test:slot:sha256:1111",
		"merlin:scan:test:slot:sha256:2222",
		"merlin:scan:test:slot:sha256:3333",
	}
	t.Cleanup(func() {
		for _, k := range keys {
			_ = s.rdb.Del(ctx, k).Err()
		}
	})
	for _, k := range keys {
		if err := s.Set(ctx, k, []byte("v"), time.Minute); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
		if _, found, err := s.Get(ctx, k); err != nil || !found {
			t.Fatalf("Get %s: found=%v err=%v", k, found, err)
		}
	}
}

var _ = redis.Nil
