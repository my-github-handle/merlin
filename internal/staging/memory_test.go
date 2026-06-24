package staging

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestMemoryBlobStoreRoundTrip(t *testing.T) {
	bs := NewMemoryBlobStore()
	ctx := context.Background()
	if err := bs.Put(ctx, "k", bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatal(err)
	}
	rc, err := bs.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestMemorySessionOffsetCAS(t *testing.T) {
	ss := NewMemorySessionStore()
	ctx := context.Background()
	_ = ss.Begin(ctx, "u1")
	ok, err := ss.CompareAndSetOffset(ctx, "u1", 0, 5)
	if err != nil || !ok {
		t.Fatalf("first CAS should succeed: ok=%v err=%v", ok, err)
	}
	ok, _ = ss.CompareAndSetOffset(ctx, "u1", 0, 10) // stale expected
	if ok {
		t.Error("CAS with stale expected offset must fail")
	}
}

func TestMemoryAllComplete(t *testing.T) {
	ss := NewMemorySessionStore()
	ctx := context.Background()
	_ = ss.Begin(ctx, "u1")
	_ = ss.MarkComplete(ctx, "u1", "sha256:a")
	all, _ := ss.AllComplete(ctx, []string{"sha256:a"})
	if !all {
		t.Error("expected all complete")
	}
	all, _ = ss.AllComplete(ctx, []string{"sha256:a", "sha256:b"})
	if all {
		t.Error("missing digest should make AllComplete false")
	}
}
