//go:build mage

// Mage build targets for Merlin. Run `mage -l` to list, `mage <target>` to run.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/magefile/mage/sh"
)

// Build compiles the merlin binary into ./bin/merlin.
func Build() error {
	if err := os.MkdirAll("bin", 0o755); err != nil {
		return err
	}
	return sh.Run("go", "build", "-o", "bin/merlin", "./cmd/merlin")
}

// Test runs the hermetic unit test suite.
func Test() error {
	return sh.Run("go", "test", "./...")
}

// TestCover runs tests with coverage and prints a per-package summary.
func TestCover() error {
	return sh.Run("go", "test", "-cover", "./...")
}

// Integration runs every test behind the `integration` build tag WITH its backends
// provisioned.
//
// It used to just run the tag and hope. Six files sit behind it, and all of them gate
// on MERLIN_VALKEY_ADDR or MERLIN_CLICKHOUSE_DSN and SKIP when the variable is absent
// — which this target never set. So it reported success while running almost none of
// them: exactly how internal/promote sat at a reported 64.4% with a full queue-
// conformance suite that had never executed. Providing the two backends is the whole
// fix; not one test needed changing, and internal/alert went 67.1% -> 81.6% on the
// strength of tests that were already written.
//
// internal/app is the exception that FAILS rather than skips (see wiring_live_test.go),
// so this target can no longer go green while doing nothing.
//
// EACH PACKAGE GETS ITS OWN ClickHouse DATABASE, and it must. The first provisioned run
// failed in internal/alert — not because those tests are wrong, they pass alone, but
// because `go test ./...` runs packages in PARALLEL and internal/audit was inserting
// rows into the same database internal/alert was counting. One shared database makes
// every count assertion depend on which sibling package happened to be mid-test. That
// was invisible while the suites skipped.
func Integration() error {
	if err := checkIntegrationPackages(); err != nil {
		return err
	}
	if err := startTestValkey(); err != nil {
		return err
	}
	defer removeValkeyTestContainer()
	if err := startTestClickHouse(); err != nil {
		return err
	}
	defer removeClickHouseTestContainer()

	for _, p := range integrationPackages {
		env := testBackendEnv()
		env["MERLIN_CLICKHOUSE_DSN"] = clickhouseDSN(p.database)
		if err := sh.RunWithV(env, "go", "test", "-count=1", "-tags", "integration", "-cover", p.dir); err != nil {
			return err
		}
	}
	return nil
}

// integrationPackages is every package holding `//go:build integration` tests, each
// with a private database. checkIntegrationPackages keeps this list honest.
var integrationPackages = []struct{ dir, database string }{
	{"./internal/app/", "merlin_it_app"},
	{"./internal/audit/", "merlin_it_audit"},
	{"./internal/alert/", "merlin_it_alert"},
	{"./internal/promote/", "merlin_it_promote"},
	{"./internal/staging/", "merlin_it_staging"},
}

// checkIntegrationPackages fails if a package grew an integration-tagged test without
// being added above. Without this guard the list rots silently and a new suite simply
// never runs — the exact failure this target was rewritten to eliminate, reintroduced
// one forgotten line at a time.
func checkIntegrationPackages() error {
	out, err := sh.Output("grep", "-rl", "go:build integration", "./internal", "./cmd")
	if err != nil {
		return fmt.Errorf("scan for integration-tagged tests: %w", err)
	}
	listed := map[string]bool{}
	for _, p := range integrationPackages {
		listed[strings.Trim(p.dir, "./")] = true
	}
	var missing []string
	for _, f := range strings.Fields(out) {
		dir := strings.Trim(f[:strings.LastIndex(f, "/")], "./")
		if !listed[dir] && !containsString(missing, dir) {
			missing = append(missing, dir)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("these packages have integration-tagged tests but are not in "+
			"integrationPackages, so `mage integration` would never run them: %s",
			strings.Join(missing, ", "))
	}
	return nil
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func clickhouseDSN(db string) string {
	return "clickhouse://default@localhost:" + clickhouseTestPort + "/" + db
}

// testBackendEnv is the pair of variables every integration suite in this repo gates
// on. Kept in one place so a new suite cannot be wired to a third spelling.
func testBackendEnv() map[string]string {
	return map[string]string{
		"MERLIN_VALKEY_ADDR":    "localhost:" + valkeyTestPort,
		"MERLIN_CLICKHOUSE_DSN": clickhouseDSN("merlin_wiring"),
	}
}

// valkeyTestContainer is the throwaway Valkey that TestPromoteQueue provisions, and
// the port it binds. 6399 rather than 6379 so it cannot collide with a Valkey a
// developer is already running. The ClickHouse pair follows the same rule against 9000.
const (
	valkeyTestContainer = "merlin-promote-test"
	valkeyTestPort      = "6399"

	clickhouseTestContainer = "merlin-app-test-ch"
	clickhouseTestPort      = "9010"

	// PINNED TO PRODUCTION'S MAJOR.MINOR, and this is load-bearing rather than
	// hygiene. The deployed ClickHouse is 26.7.3.19. On 24.10 the audit schema's
	// bootstrap FAILS outright — `TTL ts + INTERVAL n DAY` where ts is
	// DateTime64(3) is rejected with "code: 450, TTL expression result column
	// should have DateTime or Date type" — so every suite here would fail for a
	// reason that does not exist in production, and the natural response to that is
	// to weaken the test. The mirror image of the Valkey lesson below: a
	// version-mismatched backend lies in whichever direction is convenient.
	clickhouseTestImage = "clickhouse/clickhouse-server:26.7-alpine"
)

// TestAppWiring runs internal/app's live-wiring suite against a throwaway Valkey and
// ClickHouse.
//
// This is the only thing that covers BuildWithBackends at all. It is 61.5% of the
// package's statements and cannot be ENTERED without live clients — the session store
// pings on construction and the audit writer bootstraps its schema — so with the
// hermetic suite alone the package tops out near 45% no matter how good the tests are.
// Coverage from this target is therefore NOT comparable to a plain `go test` figure,
// and the refactoring plan records both numbers rather than the flattering one.
func TestAppWiring() error {
	if err := startTestValkey(); err != nil {
		return err
	}
	defer removeValkeyTestContainer()
	if err := startTestClickHouse(); err != nil {
		return err
	}
	defer removeClickHouseTestContainer()

	// RunWithV, not RunWith: the coverage line IS the result of this target.
	return sh.RunWithV(testBackendEnv(),
		"go", "test", "-count=1", "-race", "-tags", "integration",
		"-cover", "./internal/app/",
	)
}

// startTestClickHouse boots a ClickHouse whose version matches production's. No
// password: the DSN connects as `default`, and the audit writer needs to reach the
// `default` database to run CREATE DATABASE before bootstrapping its own.
func startTestClickHouse() error {
	removeClickHouseTestContainer()
	if err := sh.Run("docker", "run", "-d", "--name", clickhouseTestContainer,
		"-p", clickhouseTestPort+":9000",
		"-e", "CLICKHOUSE_SKIP_USER_SETUP=1",
		clickhouseTestImage); err != nil {
		return fmt.Errorf("start clickhouse: %w", err)
	}
	return waitForClickHouse()
}

func removeClickHouseTestContainer() {
	out, err := sh.Output("docker", "ps", "-aq", "--filter", "name=^"+clickhouseTestContainer+"$")
	if err != nil || strings.TrimSpace(out) == "" {
		return
	}
	_ = sh.Run("docker", "rm", "-f", clickhouseTestContainer)
}

// waitForClickHouse allows far longer than the Valkey wait: ClickHouse takes several
// seconds to open its native port, and a too-short wait fails as though the schema
// were wrong.
//
// It probes BOTH the server (via docker exec) and the published port from the host,
// because they become ready at different moments and only the second is the path the
// tests use. Probing exec alone produced a run where every internal/app test failed on
// a refused connection while this function had already reported success — a readiness
// check that does not exercise the caller's route is not a readiness check.
func waitForClickHouse() error {
	for i := 0; i < 150; i++ {
		if err := sh.Run("docker", "exec", clickhouseTestContainer,
			"clickhouse-client", "--query", "SELECT 1"); err == nil {
			if c, derr := net.DialTimeout("tcp", "localhost:"+clickhouseTestPort, time.Second); derr == nil {
				_ = c.Close()
				return nil
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	return fmt.Errorf("clickhouse did not accept queries on localhost:%s within 60s", clickhouseTestPort)
}

// TestPromoteQueue runs internal/promote's integration suite against a throwaway
// Valkey in Docker.
//
// CLUSTER MODE IS THE POINT, not incidental. The deployed Valkey reports
// cluster_enabled:1, and a cluster refuses any multi-key command whose keys hash to
// different slots. internal/promote's Claim and Recover are multi-key EVALs, so they
// once failed with CROSSSLOT on every single call — the worker could not drain a
// queue whose clients had already been answered 201, and approved images silently
// never reached ACR. A single-node Valkey started WITHOUT --cluster-enabled accepts
// those EVALs happily and would have passed the whole suite while that bug was live.
//
// One node owning all 16384 slots is what makes a plain (non-cluster) client work
// against it while the slot rule is still enforced.
func TestPromoteQueue() error {
	if err := startTestValkey(); err != nil {
		return err
	}
	defer removeValkeyTestContainer()

	// RunWithV, not RunWith: the coverage line is the result of this target, and
	// hiding it behind `mage -v` makes a run that covered nothing look identical to
	// one that covered everything.
	return sh.RunWithV(
		map[string]string{"MERLIN_VALKEY_ADDR": "localhost:" + valkeyTestPort},
		"go", "test", "-count=1", "-race", "-tags", "integration",
		"-cover", "./internal/promote/",
	)
}

// startTestValkey boots the throwaway Valkey in CLUSTER MODE with one node owning all
// 16384 slots. See TestPromoteQueue's comment for why cluster mode is the point rather
// than a detail; internal/app needs it for the same reason, because the promotion
// worker BuildWithBackends starts issues the same multi-key EVALs.
func startTestValkey() error {
	removeValkeyTestContainer()
	if err := sh.Run("docker", "run", "-d", "--name", valkeyTestContainer,
		"-p", valkeyTestPort+":6379", "valkey/valkey:8-alpine",
		"valkey-server", "--cluster-enabled", "yes", "--appendonly", "no", "--save", ""); err != nil {
		return fmt.Errorf("start valkey: %w", err)
	}
	if err := waitForValkey(); err != nil {
		return err
	}
	if err := sh.Run("docker", "exec", valkeyTestContainer,
		"valkey-cli", "cluster", "addslotsrange", "0", "16383"); err != nil {
		return fmt.Errorf("assign cluster slots: %w", err)
	}
	// cluster_state stays `fail` for a moment after the slots land, and commands are
	// refused until it is `ok`.
	return waitForClusterOK()
}

// removeValkeyTestContainer deletes the throwaway container if it exists. The
// existence check is not redundant: `docker rm -f` on a missing container writes
// "Error response from daemon" to stderr, and a target that prints an error on a
// healthy run teaches people to ignore its errors.
func removeValkeyTestContainer() {
	out, err := sh.Output("docker", "ps", "-aq", "--filter", "name=^"+valkeyTestContainer+"$")
	if err != nil || strings.TrimSpace(out) == "" {
		return
	}
	_ = sh.Run("docker", "rm", "-f", valkeyTestContainer)
}

func waitForValkey() error {
	for i := 0; i < 50; i++ {
		if err := sh.Run("docker", "exec", valkeyTestContainer, "valkey-cli", "ping"); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("valkey did not accept connections within 10s")
}

func waitForClusterOK() error {
	for i := 0; i < 50; i++ {
		out, err := sh.Output("docker", "exec", valkeyTestContainer, "valkey-cli", "cluster", "info")
		if err == nil && strings.Contains(out, "cluster_state:ok") {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("cluster did not reach state ok within 10s")
}

// Tidy runs go mod tidy.
func Tidy() error {
	return sh.Run("go", "mod", "tidy")
}

// Vet runs go vet across all packages.
func Vet() error {
	return sh.Run("go", "vet", "./...")
}

// Lint runs gofmt -l and fails if any file is unformatted.
func Lint() error {
	out, err := exec.Command("gofmt", "-l", ".").Output()
	if err != nil {
		return err
	}
	if len(out) > 0 {
		fmt.Printf("unformatted files:\n%s", out)
		return fmt.Errorf("gofmt found unformatted files")
	}
	return nil
}

// Clean removes build artifacts.
func Clean() error {
	return os.RemoveAll("bin")
}
