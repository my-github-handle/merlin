package limitexec

import (
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
	req, err := parseRequest([]string{"2147483648", "grype", "/oci/path", "-q"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.bytes != 2<<30 {
		t.Errorf("bytes = %d, want %d", req.bytes, uint64(2<<30))
	}
	if req.binary != "grype" {
		t.Errorf("binary = %q, want grype", req.binary)
	}
	// argv[0] must be the binary itself: exec replaces the process, and a child
	// that sees a shifted argv misparses its own flags.
	want := []string{"grype", "/oci/path", "-q"}
	if strings.Join(req.argv, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v, want %v", req.argv, want)
	}
}

func TestParseRequestRejectsBadInput(t *testing.T) {
	tests := map[string][]string{
		"no args":       {},
		"only bytes":    {"1024"},
		"unparseable":   {"lots", "grype"},
		"negative":      {"-1", "grype"},
		"zero limit":    {"0", "grype"},
		"empty binary":  {"1024", ""},
		"float bytes":   {"1024.5", "grype"},
		"suffixed size": {"2Gi", "grype"},
	}
	for name, args := range tests {
		if _, err := parseRequest(args); err == nil {
			t.Errorf("%s: parseRequest(%v) = nil error, want error", name, args)
		}
	}
}

// The hard address-space ceiling must sit above the budget, not on it: a Go
// child's virtual footprint exceeds its live heap, so RLIMIT_AS == budget would
// fail scans that never exceeded the budget.
func TestAddressSpaceLimitExceedsBudget(t *testing.T) {
	budget := uint64(2 << 30)
	got := addressSpaceLimit(budget)
	if got <= budget {
		t.Errorf("addressSpaceLimit(%d) = %d, want > budget", budget, got)
	}
	if got != 4<<30 {
		t.Errorf("addressSpaceLimit(%d) = %d, want %d", budget, got, uint64(4<<30))
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
