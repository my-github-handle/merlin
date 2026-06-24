//go:build integration

package staging

import (
	"context"
	"os"
	"testing"
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
