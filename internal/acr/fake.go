package acr

import (
	"context"
	"sync"
)

// FakePusher records push targets for tests. It is safe for concurrent use so
// it can back concurrency/race tests.
type FakePusher struct {
	Err error

	mu     sync.Mutex
	Pushed []string
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
