package acr

import "context"

// FakePusher records push targets for tests.
type FakePusher struct {
	Pushed []string
	Err    error
}

func (f *FakePusher) Push(_ context.Context, _, target string) error {
	if f.Err != nil {
		return f.Err
	}
	f.Pushed = append(f.Pushed, target)
	return nil
}
