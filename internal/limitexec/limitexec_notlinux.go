//go:build !linux

package limitexec

import (
	"fmt"
	"runtime"
)

// Main reports that memory-bounded exec is unavailable on this platform.
//
// RLIMIT_AS is not meaningfully enforced outside Linux, so rather than exec the
// child with a bound that silently does nothing, this fails loudly. Merlin runs
// in a Linux container in every deployed environment; a developer hitting this
// on macOS should leave grype.memory_limit unset, which skips the trampoline
// entirely.
func Main(args []string) error {
	if _, err := parseRequest(args); err != nil {
		return err
	}
	return fmt.Errorf("memory-bounded exec is only supported on linux, not %s: unset grype.memory_limit to run unbounded", runtime.GOOS)
}
