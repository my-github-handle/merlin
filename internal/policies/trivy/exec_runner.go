package trivy

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

// NewExecRunner returns a Runner that shells out to the trivy binary.
func NewExecRunner(binary string) Runner {
	return &execRunner{
		binary: binary,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		},
	}
}

func (e *execRunner) Scan(ctx context.Context, ociPath string) (Report, error) {
	out, err := e.run(ctx, e.binary,
		"image", "--input", ociPath, "--format", "json", "--quiet")
	if err != nil {
		return Report{}, fmt.Errorf("run trivy: %w", err)
	}
	return ParseReport(out)
}
