package limitexec

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandBuildsTrampolineArgv(t *testing.T) {
	name, args := Command("/usr/local/bin/merlin", 2<<30, "grype", []string{"/oci/path", "-o", "json"})
	if name != "/usr/local/bin/merlin" {
		t.Errorf("name = %q, want the merlin binary", name)
	}
	want := []string{Flag, "2147483648", "grype", "/oci/path", "-o", "json"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", args, want)
	}
}

func TestParseRequestBytesAndArgv(t *testing.T) {
	bin := onPathBinary(t)
	req, err := parseRequest([]string{"2147483648", bin.name, "/oci/path", "-q"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.bytes != 2<<30 {
		t.Errorf("bytes = %d, want %d", req.bytes, uint64(2<<30))
	}
	if req.binary != bin.path {
		t.Errorf("binary = %q, want the resolved path %q", req.binary, bin.path)
	}
	// argv[0] must be the binary itself: exec replaces the process, and a child
	// that sees a shifted argv misparses its own flags.
	want := []string{bin.path, "/oci/path", "-q"}
	if strings.Join(req.argv, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v, want %v", req.argv, want)
	}
}

// The trampoline reaches the child through syscall.Exec, which — unlike
// exec.Command — does NO PATH lookup and fails with ENOENT on a bare name. Callers
// hand this package the same name they would hand os/exec ("grype"), so the lookup
// has to happen here or every bounded scan dies with "no such file or directory".
// That is not a degraded scan but a failed one: the gate is fail-closed, so it
// rejected every push with a 500 until this was fixed.
func TestParseRequestResolvesBareNameAgainstPath(t *testing.T) {
	bin := onPathBinary(t)
	req, err := parseRequest([]string{"1024", bin.name})
	if err != nil {
		t.Fatalf("parseRequest(%q): %v", bin.name, err)
	}
	if !filepath.IsAbs(req.binary) {
		t.Errorf("binary = %q, want an absolute path (syscall.Exec does not search PATH)", req.binary)
	}
	if req.binary != bin.path {
		t.Errorf("binary = %q, want %q", req.binary, bin.path)
	}
}

// An explicit path must survive unchanged: resolution may not rewrite a caller that
// already said exactly which binary it means.
func TestParseRequestKeepsExplicitPath(t *testing.T) {
	bin := onPathBinary(t)
	req, err := parseRequest([]string{"1024", bin.path})
	if err != nil {
		t.Fatalf("parseRequest(%q): %v", bin.path, err)
	}
	if req.binary != bin.path {
		t.Errorf("binary = %q, want %q unchanged", req.binary, bin.path)
	}
}

func TestParseRequestRejectsBadInput(t *testing.T) {
	tests := map[string][]string{
		"no args":       {},
		"only bytes":    {"1024"},
		"unparseable":   {"lots", "sh"},
		"negative":      {"-1", "sh"},
		"zero limit":    {"0", "sh"},
		"empty binary":  {"1024", ""},
		"float bytes":   {"1024.5", "sh"},
		"suffixed size": {"2Gi", "sh"},
		// Reported at parse time, not as an opaque ENOENT from exec: a missing
		// scanner binary is a deployment fault and has to name itself.
		"binary not on path": {"1024", "merlin-no-such-binary-xyz"},
		"missing abs path":   {"1024", "/nonexistent/merlin-no-such-binary-xyz"},
	}
	for name, args := range tests {
		if _, err := parseRequest(args); err == nil {
			t.Errorf("%s: parseRequest(%v) = nil error, want error", name, args)
		}
	}
}

// onPathBinary returns a real executable reachable by bare name, so the resolution
// tests assert against the host's actual PATH rather than a fabricated one.
type pathBinary struct{ name, path string }

func onPathBinary(t *testing.T) pathBinary {
	t.Helper()
	for _, name := range []string{"sh", "true", "env"} {
		if p, err := exec.LookPath(name); err == nil {
			return pathBinary{name: name, path: p}
		}
	}
	t.Skip("no reference binary (sh/true/env) on PATH")
	return pathBinary{}
}

// The hard address-space ceiling must sit above the budget, not on it: a Go
// child's virtual footprint exceeds its live heap, so RLIMIT_AS == budget would
// fail scans that never exceeded the budget.
//
// The factor was 2x, and 2x was measured to be too tight. 115 audit rows across
// two c3.ai/opensearch-dashboards-fips tags died with a live heap of 2.52-2.72
// GiB under a 2Gi budget: the heap itself was inside 2x (4 GiB), but the
// runtime's arena and stack reservations on top of it cleared the ceiling, so
// RLIMIT_AS killed scans that GOMEMLIMIT was still controlling. That inverts the
// intended roles — GOMEMLIMIT is the control, RLIMIT_AS only catches runaways.
func TestAddressSpaceLimitExceedsBudget(t *testing.T) {
	const observedHeapAtOOM = 2920 << 20 // 2.72 GiB live + the 232 MiB block that failed

	for _, tc := range []struct {
		name   string
		budget uint64
		want   uint64
	}{
		{"1Gi", 1 << 30, 4 << 30},
		{"2Gi", 2 << 30, 8 << 30},
		{"4Gi production budget", 4 << 30, 16 << 30},
	} {
		if got := addressSpaceLimit(tc.budget); got != tc.want {
			t.Errorf("addressSpaceLimit(%s) = %d, want %d", tc.name, got, tc.want)
		}
	}

	// The regression that motivated the change: the ceiling derived from the
	// production budget must clear the largest heap ever observed, with room for
	// the runtime reservations that are not counted in that figure.
	if got := addressSpaceLimit(4 << 30); got <= observedHeapAtOOM {
		t.Errorf("addressSpaceLimit(4Gi) = %d, want > largest observed heap %d", got, uint64(observedHeapAtOOM))
	}

	// Saturate instead of wrapping: a wrapped value would be a tiny limit that
	// fails every scan, which is worse than an ineffective one.
	if got := addressSpaceLimit(^uint64(0) - 1); got != ^uint64(0) {
		t.Errorf("addressSpaceLimit(near-max) = %d, want saturation to %d", got, ^uint64(0))
	}
}

// GOMEMLIMIT carries the budget verbatim — it is the bound that actually holds
// the resident set down, and therefore the figure capacity planning uses. Any
// inherited GOMEMLIMIT is replaced rather than shadowed, since duplicate keys in
// an env slice resolve inconsistently.
func TestWithGoMemLimitReplacesInheritedValue(t *testing.T) {
	env := withGoMemLimit([]string{"PATH=/bin", "GOMEMLIMIT=99GiB", "HOME=/root"}, 2<<30)
	var seen int
	for _, kv := range env {
		if strings.HasPrefix(kv, "GOMEMLIMIT=") {
			seen++
			if kv != "GOMEMLIMIT=2147483648" {
				t.Errorf("GOMEMLIMIT = %q, want 2147483648", kv)
			}
		}
	}
	if seen != 1 {
		t.Errorf("GOMEMLIMIT appears %d times, want exactly 1: %v", seen, env)
	}
	for _, want := range []string{"PATH=/bin", "HOME=/root"} {
		if !contains(env, want) {
			t.Errorf("env dropped %q: %v", want, env)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
