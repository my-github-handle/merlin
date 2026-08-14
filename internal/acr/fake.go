package acr

import (
	"context"
	"sync"
)

// FakePusher records push targets for tests. It is safe for concurrent use so
// it can back concurrency/race tests.
type FakePusher struct {
	Err error

	// ManifestErrs is consumed one entry per PushManifest call, in order, before Err
	// applies; once exhausted the call succeeds. It exists so a test can make a
	// forward fail and then start working, which is the only way to exercise a retry
	// policy — a single Err field can express "always broken" but not "not yet".
	ManifestErrs []error

	mu             sync.Mutex
	manifestCalls  int
	Pushed         []string
	PushedManifest []string // targets passed to PushManifest (verbatim forwards)
	PushedBlob     []string // repos passed to PushBlob (attestation blob seeding)
}

// ManifestAttempts is every PushManifest call, including the ones that failed.
// PushedManifest records only successes, so it cannot tell "retried twice and
// succeeded" from "succeeded first try".
func (f *FakePusher) ManifestAttempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.manifestCalls
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifestCalls++
	if len(f.ManifestErrs) > 0 {
		err := f.ManifestErrs[0]
		f.ManifestErrs = f.ManifestErrs[1:]
		if err != nil {
			return err
		}
	} else if f.Err != nil {
		return f.Err
	}
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
