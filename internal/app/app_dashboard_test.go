package app

import (
	"context"
	"testing"

	"github.com/merlin-gate/merlin/internal/config"
)

// When dashboard_addr is empty, BuildWithBackends must still return (no dashboard
// server) and must not require any dashboard config. We only assert the arity/typing
// compiles and that validation of OTHER required fields still triggers first.
func TestBuildWithBackendsArityCompiles(t *testing.T) {
	// Missing required production fields -> error, but the 5-value signature must hold.
	_, _, _, _, err := BuildWithBackends(context.Background(), config.Config{})
	if err == nil {
		t.Fatal("expected validation error on empty config")
	}
}
