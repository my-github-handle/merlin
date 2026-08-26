// Package scancache stores grype scan reports so an identical manifest digest
// does not have to be re-scanned.
//
// It is a byte KV and nothing more: what goes in the value, and when a value stops
// being trustworthy, are decisions for internal/policies/grype, which owns the
// report and knows the vulnerability DB it came from. This package's only job is
// to make that store shared across replicas and self-expiring, and — above all —
// to stay out of the way when it is broken.
package scancache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultOpTimeout bounds a single cache operation.
//
// The cache is read and written on the gate's critical path, inside the scan slot,
// under a context bounded only by gateTimeout (5m). Without a much tighter
// deadline of its own, a hung Valkey would add minutes to every push this exists
// to make faster — and would do it to the FIRST push of every image, which cannot
// benefit from the cache at all. 2s is far above a healthy in-cluster round trip
// and far below anything a client would wait for.
const DefaultOpTimeout = 2 * time.Second

// ValkeyStore is a Valkey-backed report store.
//
// Only single-key GET and SET are ever issued. That is what lets it run against
// the deployed Valkey without hash tags: cluster mode rejects a multi-key command
// whose keys land in different slots, and content-addressed keys cannot be
// co-located by construction.
type ValkeyStore struct {
	rdb       *redis.Client
	opTimeout time.Duration
}

// NewValkeyStore wraps an existing client. A non-positive opTimeout uses
// DefaultOpTimeout — zero is not "no timeout", because an unbounded cache read on
// the push path is the failure mode this parameter exists to prevent.
func NewValkeyStore(rdb *redis.Client, opTimeout time.Duration) *ValkeyStore {
	if opTimeout <= 0 {
		opTimeout = DefaultOpTimeout
	}
	return &ValkeyStore{rdb: rdb, opTimeout: opTimeout}
}

// NewValkeyStoreAtAddr dials addr and verifies the connection before returning, so
// a misconfigured address fails at startup rather than silently disabling reuse.
func NewValkeyStoreAtAddr(addr string, opTimeout time.Duration) (*ValkeyStore, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), DefaultOpTimeout)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("connect valkey for scan cache: %w", err)
	}
	return NewValkeyStore(rdb, opTimeout), nil
}

// Get returns the stored value for key.
//
// An absent key is (nil, false, nil), not an error. A miss is the normal state for
// the first push of any image, so reporting it as a fault would log noise on every
// genuinely new digest and bury the reads that really did fail.
func (s *ValkeyStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.opTimeout)
	defer cancel()
	val, err := s.rdb.Get(ctx, key).Bytes()
	return classifyGet(val, err, key)
}

// classifyGet decides whether a read was a hit, a miss, or a fault. Split out from
// the call so the distinction can be tested without a server: it is the only
// judgement in a read, and both ways of getting it wrong are quiet. Reporting a
// miss as a fault logs noise for every genuinely new digest; reporting a fault as
// a miss makes a broken store indistinguishable from a cold one.
func classifyGet(val []byte, err error, key string) ([]byte, bool, error) {
	switch {
	case errors.Is(err, redis.Nil):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("scan cache: get %s: %w", key, err)
	}
	return val, true, nil
}

// Set stores val under key with the given expiry.
//
// A non-positive ttl is rejected rather than passed through: in go-redis, an
// expiration of 0 means "no expiry at all", so a caller's arithmetic slipping to
// zero would quietly create an immortal entry — a scan cache that never forgets is
// exactly how a superseded vulnerability DB stays in force.
func (s *ValkeyStore) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("scan cache: refusing to store %s without an expiry (ttl %s)", key, ttl)
	}
	ctx, cancel := context.WithTimeout(ctx, s.opTimeout)
	defer cancel()
	if err := s.rdb.Set(ctx, key, val, ttl).Err(); err != nil {
		return fmt.Errorf("scan cache: set %s: %w", key, err)
	}
	return nil
}

// Close releases the underlying client.
func (s *ValkeyStore) Close() error { return s.rdb.Close() }
