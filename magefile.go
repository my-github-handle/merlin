//go:build mage

// Mage build targets for Merlin. Run `mage -l` to list, `mage <target>` to run.
package main

import (
	"fmt"
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

// Integration runs tests behind the `integration` build tag (needs live backends).
//
// Tests whose backend is absent SKIP rather than fail, so a green run here does not
// mean they ran. For the promotion queue — the one backend that can be provisioned
// locally — use TestPromoteQueue, which supplies it.
func Integration() error {
	return sh.Run("go", "test", "-tags", "integration", "./...")
}

// valkeyTestContainer is the throwaway Valkey that TestPromoteQueue provisions, and
// the port it binds. 6399 rather than 6379 so it cannot collide with a Valkey a
// developer is already running.
const (
	valkeyTestContainer = "merlin-promote-test"
	valkeyTestPort      = "6399"
)

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
	removeValkeyTestContainer()
	if err := sh.Run("docker", "run", "-d", "--name", valkeyTestContainer,
		"-p", valkeyTestPort+":6379", "valkey/valkey:8-alpine",
		"valkey-server", "--cluster-enabled", "yes", "--appendonly", "no", "--save", ""); err != nil {
		return fmt.Errorf("start valkey: %w", err)
	}
	defer removeValkeyTestContainer()

	if err := waitForValkey(); err != nil {
		return err
	}
	if err := sh.Run("docker", "exec", valkeyTestContainer,
		"valkey-cli", "cluster", "addslotsrange", "0", "16383"); err != nil {
		return fmt.Errorf("assign cluster slots: %w", err)
	}
	// cluster_state stays `fail` for a moment after the slots land, and commands are
	// refused until it is `ok`.
	if err := waitForClusterOK(); err != nil {
		return err
	}

	// RunWithV, not RunWith: the coverage line is the result of this target, and
	// hiding it behind `mage -v` makes a run that covered nothing look identical to
	// one that covered everything.
	return sh.RunWithV(
		map[string]string{"MERLIN_VALKEY_ADDR": "localhost:" + valkeyTestPort},
		"go", "test", "-count=1", "-race", "-tags", "integration",
		"-cover", "./internal/promote/",
	)
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
