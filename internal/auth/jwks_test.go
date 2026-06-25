package auth

import (
	"context"
	"testing"
)

func TestNewEntraKeyfuncRequiresURL(t *testing.T) {
	if _, err := NewEntraKeyfunc(context.Background(), ""); err == nil {
		t.Error("expected error for empty jwks URL")
	}
}
