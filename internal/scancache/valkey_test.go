package scancache

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// unreachableAddr is a port nothing listens on. These tests are not a stand-in for
// the real server — valkey_integration_test.go covers the round trips — they cover
// the branch every method has and no happy-path test reaches: what the gate is
// told when Valkey is down.
//
// The contract under test is that a broken cache costs a scan and nothing else.
// The gate is fail-closed, so a store that returned an error the caller might
// mistake for a verdict, or that blocked on a dead socket, would turn a
// throughput optimisation into an outage.
const unreachableAddr = "127.0.0.1:1"

func unreachableStore(t *testing.T) *ValkeyStore {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{
		Addr:        unreachableAddr,
		MaxRetries:  -1,
		DialTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewValkeyStore(rdb, 0)
}

func TestGetOnDeadServerReportsAnError(t *testing.T) {
	_, found, err := unreachableStore(t).Get(context.Background(), "merlin:scan:v1:sha256:x")
	if err == nil {
		t.Fatal("expected an error from a dead server")
	}
	if found {
		t.Error("found must be false when the read failed")
	}
	if !strings.Contains(err.Error(), "scan cache") {
		t.Errorf("error should name the subsystem, got %q", err)
	}
}

func TestSetOnDeadServerReportsAnError(t *testing.T) {
	err := unreachableStore(t).Set(context.Background(), "merlin:scan:v1:sha256:x", []byte("{}"), time.Hour)
	if err == nil {
		t.Fatal("expected an error from a dead server")
	}
	if !strings.Contains(err.Error(), "scan cache") {
		t.Errorf("error should name the subsystem, got %q", err)
	}
}

func TestOperationsAreBoundedByTheirOwnTimeout(t *testing.T) {
	// The cache sits on the gate's critical path, inside the scan slot, under a
	// context bounded only by gateTimeout (5m). Without its own deadline a hung
	// Valkey would add minutes to every push it was supposed to make faster.
	rdb := redis.NewClient(&redis.Options{
		Addr:       unreachableAddr,
		MaxRetries: -1,
		// Long dial timeout: only the store's own deadline can cut this short.
		DialTimeout: 30 * time.Second,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	s := NewValkeyStore(rdb, 60*time.Millisecond)

	start := time.Now()
	if _, _, err := s.Get(context.Background(), "k"); err == nil {
		t.Fatal("expected an error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Get took %v; it should be cut off by the store's own timeout", elapsed)
	}
}

func TestDefaultOpTimeoutAppliesWhenUnset(t *testing.T) {
	s := NewValkeyStore(redis.NewClient(&redis.Options{Addr: unreachableAddr}), 0)
	t.Cleanup(func() { _ = s.rdb.Close() })
	if s.opTimeout != DefaultOpTimeout {
		t.Errorf("opTimeout = %v, want the %v default", s.opTimeout, DefaultOpTimeout)
	}
}

func TestNegativeOpTimeoutAppliesTheDefault(t *testing.T) {
	s := NewValkeyStore(redis.NewClient(&redis.Options{Addr: unreachableAddr}), -time.Second)
	t.Cleanup(func() { _ = s.rdb.Close() })
	if s.opTimeout != DefaultOpTimeout {
		t.Errorf("opTimeout = %v, want the %v default", s.opTimeout, DefaultOpTimeout)
	}
}

// classifyGet holds the only real decision in a read: whether an absent key is a
// miss or a fault. Getting it wrong either logs a cache fault on the first push of
// every image, or hides a genuinely broken store behind a stream of "misses" that
// look like normal cold-cache behaviour. It is tested directly because it is the
// logic; the surrounding call is thin I/O covered by the integration tests.
func TestClassifyGetTreatsAbsentKeyAsAMiss(t *testing.T) {
	val, found, err := classifyGet(nil, redis.Nil, "k")
	if err != nil {
		t.Errorf("a miss must not be an error, got %v", err)
	}
	if found {
		t.Error("found must be false on a miss")
	}
	if val != nil {
		t.Errorf("value must be nil on a miss, got %q", val)
	}
}

func TestClassifyGetReturnsTheValueOnAHit(t *testing.T) {
	val, found, err := classifyGet([]byte("payload"), nil, "k")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || string(val) != "payload" {
		t.Errorf("got (%q, %v), want (\"payload\", true)", val, found)
	}
}

func TestClassifyGetWrapsARealFailure(t *testing.T) {
	val, found, err := classifyGet(nil, errors.New("connection reset"), "merlin:scan:v1:sha256:abc")
	if err == nil {
		t.Fatal("expected a real error to be reported")
	}
	if found || val != nil {
		t.Errorf("a failed read must not look like a hit, got (%q, %v)", val, found)
	}
	// The key is in the message because it is the only way to tell which digest's
	// read failed when several pushes are in flight.
	if !strings.Contains(err.Error(), "sha256:abc") || !strings.Contains(err.Error(), "scan cache") {
		t.Errorf("error should name the subsystem and the key, got %q", err)
	}
}

func TestSetRefusesAnEntryWithoutAnExpiry(t *testing.T) {
	// In go-redis an expiration of 0 means "never expire". A caller whose TTL
	// arithmetic slipped to zero would silently create an immortal entry, which is
	// how a superseded vulnerability DB stays in force. This must never reach the
	// server, so it is asserted against a store that has none.
	s := unreachableStore(t)
	for _, ttl := range []time.Duration{0, -time.Second} {
		err := s.Set(context.Background(), "merlin:scan:v1:sha256:x", []byte("{}"), ttl)
		if err == nil {
			t.Fatalf("ttl %v must be rejected", ttl)
		}
		if !strings.Contains(err.Error(), "expiry") {
			t.Errorf("ttl %v: error should explain the missing expiry, got %q", ttl, err)
		}
	}
}

func TestCloseReleasesTheClient(t *testing.T) {
	s := NewValkeyStore(redis.NewClient(&redis.Options{Addr: unreachableAddr}), 0)
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNewValkeyStoreAtAddrFailsFastOnABadAddress(t *testing.T) {
	// A misconfigured address must fail at startup, not on the first push.
	if _, err := NewValkeyStoreAtAddr(unreachableAddr, 50*time.Millisecond); err == nil {
		t.Fatal("expected a connection error for an unreachable address")
	}
}
