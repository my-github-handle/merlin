package grype

import (
	"context"
	"strings"
	"testing"

	"github.com/merlin-gate/merlin/internal/limitexec"
)

const okReport = `{"matches":[],"descriptor":{"db":{"schemaVersion":5,"built":"2026-07-16T00:00:00Z"}}}`

// With no limit configured the argv must be untouched: the trampoline is opt-in
// because config cannot know the pod's memory limit.
func TestExecRunnerWithoutMemoryLimitExecsGrypeDirectly(t *testing.T) {
	var gotName string
	var gotArgs []string
	er := &execRunner{
		binary: "grype",
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotName, gotArgs = name, args
			return []byte(okReport), nil
		},
	}
	if _, err := er.Scan(context.Background(), "/oci/path"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotName != "grype" {
		t.Errorf("name = %q, want grype", gotName)
	}
	if strings.Contains(strings.Join(gotArgs, " "), limitexec.Flag) {
		t.Errorf("argv should not be wrapped when no limit is set: %v", gotArgs)
	}
}

// With a limit configured merlin re-execs itself as a trampoline, which sets
// the child's memory bound and then exec's grype. Grype's own flags must be
// preserved verbatim after the trampoline prefix.
func TestExecRunnerWithMemoryLimitWrapsInTrampoline(t *testing.T) {
	var gotName string
	var gotArgs []string
	er := &execRunner{
		binary:        "grype",
		self:          "/usr/local/bin/merlin",
		memLimitBytes: 2 << 30,
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotName, gotArgs = name, args
			return []byte(okReport), nil
		},
	}
	if _, err := er.Scan(context.Background(), "/oci/path"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotName != "/usr/local/bin/merlin" {
		t.Errorf("name = %q, want the merlin binary", gotName)
	}
	want := []string{limitexec.Flag, "2147483648", "grype", "/oci/path", "-o", "json", "-q", "--by-cve"}
	if strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v, want %v", gotArgs, want)
	}
}

// If merlin cannot locate its own binary the trampoline is impossible. Fail the
// scan rather than silently scanning unbounded: unbounded scans are what the
// limit exists to prevent, and a silent downgrade is undetectable in prod.
func TestExecRunnerFailsWhenSelfPathUnknown(t *testing.T) {
	er := &execRunner{
		binary:        "grype",
		memLimitBytes: 2 << 30,
		selfErr:       errSelfPath,
		run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			t.Fatal("run should not be called when the trampoline cannot be built")
			return nil, nil
		},
	}
	_, err := er.Scan(context.Background(), "/oci/path")
	if err == nil {
		t.Fatal("expected error when self path is unknown")
	}
	if !strings.Contains(err.Error(), "memory-bounded") {
		t.Errorf("error should explain the memory bound failed, got: %v", err)
	}
}

func TestNewExecRunnerWithMemoryLimit(t *testing.T) {
	r := NewExecRunner("grype", WithMemoryLimit(2<<30))
	er, ok := r.(*execRunner)
	if !ok {
		t.Fatalf("NewExecRunner returned %T, want *execRunner", r)
	}
	if er.memLimitBytes != 2<<30 {
		t.Errorf("memLimitBytes = %d, want %d", er.memLimitBytes, int64(2<<30))
	}
	// A zero or negative limit means "unbounded" and must not engage the
	// trampoline, so it is not stored.
	for _, bad := range []int64{0, -1} {
		er := NewExecRunner("grype", WithMemoryLimit(bad)).(*execRunner)
		if er.memLimitBytes != 0 {
			t.Errorf("WithMemoryLimit(%d) = %d, want 0", bad, er.memLimitBytes)
		}
	}
}
