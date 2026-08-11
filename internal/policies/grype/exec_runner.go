package grype

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/merlin-gate/merlin/internal/limitexec"
)

type execFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

type execRunner struct {
	binary string
	run    execFunc
	// memLimitBytes > 0 routes the scan through the limitexec trampoline, which
	// bounds grype's memory. 0 runs grype directly, unbounded.
	memLimitBytes int64
	// self is the path to merlin's own binary, re-executed as the trampoline.
	// Resolved once at construction; selfErr defers the failure to Scan, where
	// it can be reported instead of silently disabling the bound.
	self    string
	selfErr error
}

// errSelfPath reports that merlin cannot locate its own binary, so the
// memory-bounding trampoline cannot be built.
var errSelfPath = errors.New("cannot resolve merlin's own executable path")

// ExecOption configures the exec-based Runner.
type ExecOption func(*execRunner)

// WithMemoryLimit bounds each grype scan to bytes of memory by re-execing
// merlin as a trampoline (see internal/limitexec). Zero or negative means
// unbounded, matching the config default.
func WithMemoryLimit(bytes int64) ExecOption {
	return func(e *execRunner) {
		if bytes <= 0 {
			return
		}
		e.memLimitBytes = bytes
		if self, err := os.Executable(); err == nil {
			e.self = self
		} else {
			e.selfErr = fmt.Errorf("%w: %v", errSelfPath, err)
		}
	}
}

// NewExecRunner returns a Runner that shells out to the grype binary.
func NewExecRunner(binary string, opts ...ExecOption) Runner {
	e := &execRunner{
		binary: binary,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		},
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

func (e *execRunner) Scan(ctx context.Context, ociPath string) (Report, error) {
	// Grype scans the assembled OCI layout directory. "-q" silences the
	// progress UI so stdout is clean JSON; "-o json" selects native output.
	// "--by-cve" orients matches by their canonical CVE (falling back to the
	// original advisory ID when no CVE mapping exists), so stored cve_id values
	// match the c3securitytools grype import pipeline.
	name, args := e.binary, []string{ociPath, "-o", "json", "-q", "--by-cve"}
	if e.memLimitBytes > 0 {
		// Fail rather than fall back to an unbounded scan: unbounded scans are
		// exactly what the limit exists to prevent, and a silent downgrade is
		// invisible until the pod is OOM-killed again.
		if e.selfErr != nil {
			return Report{}, fmt.Errorf("run grype: memory-bounded exec unavailable: %w", e.selfErr)
		}
		name, args = limitexec.Command(e.self, e.memLimitBytes, e.binary, args)
	}
	out, err := e.run(ctx, name, args...)
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
