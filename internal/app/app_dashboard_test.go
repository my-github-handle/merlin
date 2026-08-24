package app

import (
	"context"
	"testing"

	"github.com/merlin-gate/merlin/internal/config"
)

// A failed build must return the ZERO Servers, not a partly-filled one.
//
// This test used to assert only that the five-value signature compiled, which the
// compiler already guaranteed. Servers makes the real risk expressible instead: a
// caller that got an error and reached for a field anyway. Every field must be nil
// — including Close, so `defer srv.Close()` after a failed build panics loudly
// rather than double-releasing what fail() already closed.
func TestFailedBuildReturnsNothingToUse(t *testing.T) {
	srv, err := BuildWithBackends(context.Background(), config.Config{})
	if err == nil {
		t.Fatal("expected validation error on empty config")
	}
	if srv.Gate != nil || srv.Metrics != nil || srv.Dashboard != nil {
		t.Errorf("failed build returned servers: %+v", srv)
	}
	if srv.Close != nil {
		t.Error("failed build returned a Close func; fail() has already released everything")
	}
}
