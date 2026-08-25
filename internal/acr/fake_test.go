package acr

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// FakePusher is the double every other package's publish tests run against — the router,
// the promotion worker and the outcome path all assert on what it recorded. It was at 0.0%
// itself, which is the worst place for an untested line: a fake that mis-records makes the
// tests that depend on it agree with each other and with nothing real.

// The sequencing contract is the whole reason ManifestErrs exists: a retry policy can only
// be exercised by a forward that fails and then works. Three things have to hold together —
// the errors are consumed in order, the attempt count includes the failures, and
// PushedManifest records successes only.
func TestFakePusherManifestErrsAreConsumedInOrderAndOnlySuccessesRecorded(t *testing.T) {
	first := errors.New("not yet")
	f := &FakePusher{ManifestErrs: []error{first, nil}}
	ctx := context.Background()

	if err := f.PushManifest(ctx, []byte("m"), "", "r:1"); !errors.Is(err, first) {
		t.Fatalf("first call err = %v, want %v", err, first)
	}
	if err := f.PushManifest(ctx, []byte("m"), "", "r:1"); err != nil {
		t.Fatalf("second call err = %v, want nil: the queued nil must let it through", err)
	}
	// Queue exhausted: further calls succeed.
	if err := f.PushManifest(ctx, []byte("m"), "", "r:2"); err != nil {
		t.Fatalf("third call err = %v, want nil once ManifestErrs is drained", err)
	}

	if got := f.ManifestAttempts(); got != 3 {
		t.Errorf("ManifestAttempts() = %d, want 3: failed attempts must still count, or a retry test cannot see the retry", got)
	}
	if want := []string{"r:1", "r:2"}; len(f.PushedManifest) != len(want) ||
		f.PushedManifest[0] != want[0] || f.PushedManifest[1] != want[1] {
		t.Errorf("PushedManifest = %v, want %v: a failed push must not be recorded as published", f.PushedManifest, want)
	}
}

// Err is the "always broken" setting, and ManifestErrs takes precedence while it lasts.
func TestFakePusherErrAppliesToEveryMethodAndYieldsToManifestErrs(t *testing.T) {
	always := errors.New("registry down")
	ctx := context.Background()

	f := &FakePusher{Err: always}
	if err := f.Push(ctx, "/layout", "r:1"); !errors.Is(err, always) {
		t.Errorf("Push err = %v, want %v", err, always)
	}
	if err := f.PushManifest(ctx, nil, "", "r:1"); !errors.Is(err, always) {
		t.Errorf("PushManifest err = %v, want %v", err, always)
	}
	if err := f.PushBlob(ctx, nil, "", "r"); !errors.Is(err, always) {
		t.Errorf("PushBlob err = %v, want %v", err, always)
	}
	if len(f.Pushed) != 0 || len(f.PushedManifest) != 0 || len(f.PushedBlob) != 0 {
		t.Errorf("a failing fake recorded something: Pushed=%v PushedManifest=%v PushedBlob=%v",
			f.Pushed, f.PushedManifest, f.PushedBlob)
	}

	// A queued nil beats a set Err: "broken until it isn't".
	g := &FakePusher{Err: always, ManifestErrs: []error{nil}}
	if err := g.PushManifest(ctx, nil, "", "r:1"); err != nil {
		t.Errorf("queued nil did not override Err: got %v", err)
	}
	if err := g.PushManifest(ctx, nil, "", "r:2"); !errors.Is(err, always) {
		t.Errorf("after the queue drained, Err must apply again: got %v", err)
	}
}

// Push and PushBlob record the target and the repo respectively — different arguments, and
// swapping them would make an assertion about which registry was published to vacuous.
func TestFakePusherRecordsTheTargetAndTheRepo(t *testing.T) {
	f := &FakePusher{}
	ctx := context.Background()

	if err := f.Push(ctx, "/layout", "reg.io/team/app:v1"); err != nil {
		t.Fatal(err)
	}
	if err := f.PushBlob(ctx, []byte("blob"), "application/json", "reg.io/team/app"); err != nil {
		t.Fatal(err)
	}
	if len(f.Pushed) != 1 || f.Pushed[0] != "reg.io/team/app:v1" {
		t.Errorf("Pushed = %v, want the full target including the tag", f.Pushed)
	}
	if len(f.PushedBlob) != 1 || f.PushedBlob[0] != "reg.io/team/app" {
		t.Errorf("PushedBlob = %v, want the repo without a reference", f.PushedBlob)
	}
}

// The doc comment promises concurrency safety, and that promise is load-bearing: the fake
// backs the pool's race tests, so if it races itself those runs report the fake's bug as the
// pool's. Only meaningful under -race, which CI runs.
func TestFakePusherIsSafeForConcurrentUse(t *testing.T) {
	f := &FakePusher{}
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = f.Push(ctx, "/layout", "r:1")
			_ = f.PushManifest(ctx, nil, "", "r:1")
			_ = f.PushBlob(ctx, nil, "", "r")
			_ = f.ManifestAttempts()
		}()
	}
	wg.Wait()

	if got := f.ManifestAttempts(); got != 20 {
		t.Errorf("ManifestAttempts() = %d, want 20: a lost increment means the counter is not synchronised", got)
	}
	if len(f.Pushed) != 20 || len(f.PushedManifest) != 20 || len(f.PushedBlob) != 20 {
		t.Errorf("lost records: Pushed=%d PushedManifest=%d PushedBlob=%d, want 20 each",
			len(f.Pushed), len(f.PushedManifest), len(f.PushedBlob))
	}
}

// A pusher with no registry is refused at construction rather than at the first push: the
// tenant-to-registry mapping is config, so the failure belongs at startup where an operator
// sees it, not on a client's manifest PUT hours later.
func TestCredentialPushersRequireTheirIdentifyingConfig(t *testing.T) {
	if _, err := NewACRPusherWithCredential(""); err == nil ||
		err.Error() != "acr: registry is required" {
		t.Errorf("NewACRPusherWithCredential(\"\") err = %v, want it to name the missing registry", err)
	}
	if _, err := NewACRPusherWithClientID("", "cid"); err == nil ||
		err.Error() != "acr: registry is required" {
		t.Errorf("NewACRPusherWithClientID with no registry err = %v, want it to name the missing registry", err)
	}
	if _, err := NewACRPusherWithClientID("reg.io", ""); err == nil ||
		err.Error() != "acr: client id is required" {
		t.Errorf("NewACRPusherWithClientID with no client id err = %v, want it to name the missing client id", err)
	}
}
