package grype

import (
	"context"
	"fmt"
	"os/exec"
)

type execFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

type execRunner struct {
	binary string
	run    execFunc
}

// NewExecRunner returns a Runner that shells out to the grype binary.
func NewExecRunner(binary string) Runner {
	return &execRunner{
		binary: binary,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		},
	}
}

func (e *execRunner) Scan(ctx context.Context, ociPath string) (Report, error) {
	// Grype scans the assembled OCI layout directory. "-q" silences the
	// progress UI so stdout is clean JSON; "-o json" selects native output.
	out, err := e.run(ctx, e.binary, ociPath, "-o", "json", "-q")
	if err != nil {
		return Report{}, fmt.Errorf("run grype: %w", err)
	}
	return ParseReport(out)
}
