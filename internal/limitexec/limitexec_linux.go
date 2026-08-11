//go:build linux

package limitexec

import (
	"fmt"
	"os"
	"syscall"
)

// Main runs the trampoline: it applies the memory bound to itself and then
// exec's the target, replacing this process. It returns only on failure.
//
// args is os.Args[2:] — everything after the Flag.
//
// Setting RLIMIT_AS here does not unmap anything already mapped; it only fails
// future mappings. This process is a freshly started merlin that has loaded no
// config and opened no backends, so its own address space is near the Go
// runtime's baseline reservation — which is itself large enough to explain why
// the ceiling is derived from the budget rather than equal to it.
func Main(args []string) error {
	req, err := parseRequest(args)
	if err != nil {
		return err
	}
	as := addressSpaceLimit(req.bytes)
	lim := syscall.Rlimit{Cur: as, Max: as}
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &lim); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_AS=%d (budget %d): %w", as, req.bytes, err)
	}
	env := withGoMemLimit(os.Environ(), req.bytes)
	if err := syscall.Exec(req.binary, req.argv, env); err != nil {
		return fmt.Errorf("exec %s: %w", req.binary, err)
	}
	return nil // unreachable: a successful Exec does not return.
}
