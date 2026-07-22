package grype

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
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
	// "--by-cve" orients matches by their canonical CVE (falling back to the
	// original advisory ID when no CVE mapping exists), so stored cve_id values
	// match the c3securitytools grype import pipeline.
	out, err := e.run(ctx, e.binary, ociPath, "-o", "json", "-q", "--by-cve")
	if err != nil {
		// Surface grype's stderr: "exit status 1" alone is undiagnosable (DB
		// download failure, bad layout, OOM-kill all look identical without it).
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return Report{}, fmt.Errorf("run grype: %w: %s", err, truncate(string(ee.Stderr), 512))
		}
		return Report{}, fmt.Errorf("run grype: %w", err)
	}
	return ParseReport(out)
}

// truncate caps s at n bytes for error messages (audit error_detail, logs).
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
