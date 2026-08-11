// Package limitexec provides a self-re-exec trampoline that applies a memory
// bound to a child process before handing control to it.
//
// Why a trampoline: Go's os/exec cannot set resource limits on a child. The
// limits are inherited across exec, but Setrlimit applies to the calling
// process, so bounding a child requires a process that limits itself and then
// exec's the target. Merlin therefore re-execs its own binary with a hidden
// flag; that copy sets the bound and exec's the real command. No shell and no
// external helper binary is involved, so this works on a distroless image.
//
// Two bounds are applied, because neither alone is right:
//
//   - GOMEMLIMIT is the one that holds resident memory down, which is the only
//     thing a cgroup memory limit counts. The Go runtime treats it as a soft heap
//     ceiling and GCs harder as the heap approaches it, so a child that would
//     have grown without limit instead trades CPU for staying under budget. Grype
//     is a Go program, so it honors this.
//   - RLIMIT_AS is a hard backstop for allocation that GC cannot walk back. It
//     caps virtual address space, NOT resident memory, and a Go runtime reserves
//     virtual space far in excess of its live heap. Setting it to the memory
//     budget would therefore kill scans that were never over budget.
//
// So the configured budget is applied verbatim as GOMEMLIMIT, and RLIMIT_AS is
// derived from it with a multiplier for the runtime's virtual reservations.
// Capacity planning uses the budget figure, not the derived one.
package limitexec

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Flag is the hidden argv[1] that puts merlin into trampoline mode. It is not
// part of the documented CLI surface; only execRunner produces it.
const Flag = "--limited-exec"

// Command builds the argv that re-execs self as a trampoline around binary.
// Callers pass the result to exec.CommandContext unchanged.
func Command(self string, memLimitBytes int64, binary string, args []string) (string, []string) {
	out := make([]string, 0, len(args)+3)
	out = append(out, Flag, strconv.FormatInt(memLimitBytes, 10), binary)
	out = append(out, args...)
	return self, out
}

// request is a parsed trampoline invocation.
type request struct {
	bytes  uint64
	binary string
	// argv is the child's argv including argv[0] (the binary itself).
	argv []string
}

// parseRequest validates the trampoline's own arguments, i.e. os.Args[2:].
func parseRequest(args []string) (request, error) {
	if len(args) < 2 {
		return request{}, fmt.Errorf("usage: merlin %s <bytes> <binary> [args...]", Flag)
	}
	// Deliberately only plain byte counts: the human-readable form is parsed
	// once, at config load, where a bad value can still fail startup.
	n, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return request{}, fmt.Errorf("parse memory limit %q: %w", args[0], err)
	}
	if n == 0 {
		return request{}, fmt.Errorf("memory limit must be > 0, got %q", args[0])
	}
	if args[1] == "" {
		return request{}, fmt.Errorf("empty binary path")
	}
	// Resolve the binary here, because the trampoline reaches the child through
	// syscall.Exec, which does NO PATH lookup — a bare name fails with ENOENT.
	// Callers hand this package the same name they would hand os/exec ("grype"), and
	// the unbounded path DOES resolve it (exec.Command calls LookPath internally), so
	// without this the bound silently changes which binaries are reachable. LookPath
	// also covers the explicit-path case: it returns the input when it is executable
	// and errors when it is not, which turns a deployment fault into a named error
	// instead of an opaque exec failure per scan.
	binary, err := exec.LookPath(args[1])
	if err != nil {
		return request{}, fmt.Errorf("locate %q: %w", args[1], err)
	}
	// argv[0] is the resolved path, matching what the process actually is. The child's
	// own flags start at argv[1], so the shift here must mirror args[1:] exactly.
	argv := make([]string, 0, len(args)-1)
	argv = append(argv, binary)
	argv = append(argv, args[2:]...)
	return request{bytes: n, binary: binary, argv: argv}, nil
}

// addressSpaceFactor scales the memory budget into an RLIMIT_AS ceiling. A Go
// child's virtual footprint exceeds its live heap by the runtime's arena and
// stack reservations — on the order of a gigabyte before the program allocates
// anything — so the hard limit has to sit well above the budget to only catch
// genuine runaway allocation. 2x is deliberately loose: RLIMIT_AS is the
// backstop, GOMEMLIMIT is the control.
const addressSpaceFactor = 2

// addressSpaceLimit derives the RLIMIT_AS ceiling from a memory budget,
// saturating rather than wrapping so an absurd budget degrades to "unlimited in
// practice" instead of to a tiny limit that fails every scan.
func addressSpaceLimit(budget uint64) uint64 {
	const maxUint64 = ^uint64(0)
	if budget > maxUint64/addressSpaceFactor {
		return maxUint64
	}
	return budget * addressSpaceFactor
}

// withGoMemLimit returns env with GOMEMLIMIT set to bytes, replacing any
// inherited value. Duplicate keys in an environment slice resolve
// inconsistently across platforms, so the old entry is dropped rather than
// shadowed.
func withGoMemLimit(env []string, bytes uint64) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "GOMEMLIMIT=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GOMEMLIMIT="+strconv.FormatUint(bytes, 10))
}
