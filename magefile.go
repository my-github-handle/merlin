//go:build mage

// Mage build targets for Merlin. Run `mage -l` to list, `mage <target>` to run.
package main

import (
	"fmt"
	"os"
	"os/exec"

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
func Integration() error {
	return sh.Run("go", "test", "-tags", "integration", "./...")
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
