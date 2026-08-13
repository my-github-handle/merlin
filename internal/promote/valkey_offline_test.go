package promote

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// These tests run against a deliberately unreachable Valkey. That is not a stand-in
// for the real thing — valkey_integration_test.go covers the Lua and the round trips
// against a live server — it is coverage of the branch every queue method has and
// none of the happy-path tests reach: what the worker is told when Valkey is down.
//
// The assertion is on the WRAPPING, not the redis error. A bare "connection refused"
// in the promotion log says nothing about which job stalled or which operation lost
// it, and these messages are the whole audit trail for a queue whose clients have
// already been answered 201.
func unreachableQueue(t *testing.T) *valkeyQueue {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{
		Addr: unreachableAddr,
		// No retries and a short dial timeout: this test asserts an error path, so
		// go-redis's default 3 retries with backoff would only make it slow.
		MaxRetries:  -1,
		DialTimeout: 250 * time.Millisecond,
	})
	t.Cleanup(func() { rdb.Close() })
	return NewValkeyQueue(rdb, "merlin:promote:offline").(*valkeyQueue)
}

// Port 1 is reserved (tcpmux) and never bound in practice, so a dial there is
// refused immediately rather than timing out.
const unreachableAddr = "127.0.0.1:1"

func TestNewValkeyQueueAtAddrFailsFastOnABadAddress(t *testing.T) {
	q, err := NewValkeyQueueAtAddr(unreachableAddr, "merlin:promote:offline")
	if err == nil {
		t.Fatal("NewValkeyQueueAtAddr succeeded against an unreachable Valkey; " +
			"a misconfigured address must fail at startup, not on the first promotion")
	}
	if q != nil {
		t.Errorf("queue = %v, want nil alongside the error", q)
	}
	if !strings.Contains(err.Error(), "connect valkey for promote queue") {
		t.Errorf("error = %q, want it to name what failed to connect", err)
	}
}

// TestValkeyQueueOperationsWrapOutageErrors covers every method's failure branch and
// pins that the message identifies the operation — and, where the queue knows it,
// the push ID whose promotion is at risk.
func TestValkeyQueueOperationsWrapOutageErrors(t *testing.T) {
	ctx := context.Background()
	const pushID = "p-offline-1"

	tests := []struct {
		name string
		call func(q *valkeyQueue) error
		want []string // all must appear in the error
	}{
		{
			name: "enqueue",
			call: func(q *valkeyQueue) error {
				return q.Enqueue(ctx, Job{PushID: pushID, Target: "acr.io/app:v1"})
			},
			// The push ID matters most here: a failed enqueue is the one case where the
			// gate has NOT yet answered the client, so the handler can still refuse.
			want: []string{"enqueue promote job", pushID},
		},
		{
			name: "claim",
			call: func(q *valkeyQueue) error {
				j, ok, err := q.Claim(ctx)
				if ok {
					t.Errorf("Claim reported ok with job %+v during an outage; the worker would promote a zero job", j)
				}
				return err
			},
			want: []string{"claim promote job"},
		},
		{
			name: "ack",
			call: func(q *valkeyQueue) error { return q.Ack(ctx, pushID) },
			want: []string{"ack promote job", pushID},
		},
		{
			name: "depth",
			call: func(q *valkeyQueue) error {
				n, err := q.Depth(ctx)
				if n != 0 {
					t.Errorf("Depth = %d during an outage, want 0; a nonzero backlog would shed load for no reason", n)
				}
				return err
			},
			want: []string{"promote queue depth"},
		},
		{
			name: "recover",
			call: func(q *valkeyQueue) error {
				jobs, err := q.Recover(ctx, time.Minute)
				if len(jobs) != 0 {
					t.Errorf("Recover returned %d jobs during an outage, want none", len(jobs))
				}
				return err
			},
			want: []string{"recover promote claims"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(unreachableQueue(t))
			if err == nil {
				t.Fatalf("%s succeeded against an unreachable Valkey", tc.name)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}
