package acr

import (
	"context"
	"sync"
)

// FakePusher records push targets for tests. It is safe for concurrent use so
// it can back concurrency/race tests.
type FakePusher struct {
	Err error

	mu             sync.Mutex
	Pushed         []string
	PushedManifest []string // targets passed to PushManifest (verbatim forwards)
	PushedBlob     []string // repos passed to PushBlob (attestation blob seeding)
}

func (f *FakePusher) Push(_ context.Context, _, target string) error {
	if f.Err != nil {
		return f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Pushed = append(f.Pushed, target)
	return nil
}

func (f *FakePusher) PushManifest(_ context.Context, _ []byte, _ string, target string) error {
	if f.Err != nil {
		return f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.PushedManifest = append(f.PushedManifest, target)
	return nil
}

func (f *FakePusher) PushBlob(_ context.Context, _ []byte, _ string, repo string) error {
	if f.Err != nil {
		return f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.PushedBlob = append(f.PushedBlob, repo)
	return nil
}
