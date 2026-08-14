package acr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// TestIsMissingReference pins which registry errors mean "something this manifest
// points at is not here yet" — the only class an index forward may wait on.
//
// The distinction is the whole safety argument. Waiting on a genuinely broken push
// (bad target, no credentials) would turn a fast, clear failure into a slow, vague
// one; and treating any error as waitable would let the index forward retry past a
// rejection, which is what keeps an ungated image from being published by reference.
func TestIsMissingReference(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			// What ACR actually returns when an index names a sub-manifest it does not
			// have: "MANIFEST_BLOB_UNKNOWN: blob unknown to registry; sha256:cb04f117..."
			name: "manifest blob unknown",
			err: &transport.Error{
				StatusCode: http.StatusBadRequest,
				Errors:     []transport.Diagnostic{{Code: transport.ManifestBlobUnknownErrorCode, Message: "blob unknown to registry"}},
			},
			want: true,
		},
		{
			name: "blob unknown",
			err: &transport.Error{
				StatusCode: http.StatusBadRequest,
				Errors:     []transport.Diagnostic{{Code: transport.BlobUnknownErrorCode}},
			},
			want: true,
		},
		{
			// Deliberately NOT waitable. MANIFEST_UNKNOWN is a miss on the TARGET, not on
			// a reference — a wrong repo or a deleted tag — and no amount of waiting
			// makes a wrong target right.
			name: "manifest unknown is not a missing reference",
			err: &transport.Error{
				StatusCode: http.StatusNotFound,
				Errors:     []transport.Diagnostic{{Code: transport.ManifestUnknownErrorCode}},
			},
			want: false,
		},
		{
			name: "unauthorized",
			err: &transport.Error{
				StatusCode: http.StatusUnauthorized,
				Errors:     []transport.Diagnostic{{Code: transport.UnauthorizedErrorCode}},
			},
			want: false,
		},
		{
			// A manifest the registry considers malformed is a bug in what we forwarded.
			name: "manifest invalid",
			err: &transport.Error{
				StatusCode: http.StatusBadRequest,
				Errors:     []transport.Diagnostic{{Code: transport.ManifestInvalidErrorCode}},
			},
			want: false,
		},
		{name: "plain error", err: errors.New("dial tcp: connection refused"), want: false},
		{name: "nil", err: nil, want: false},
		{
			// PushManifest wraps parse failures and callers wrap again; the classification
			// has to survive that or it would only work when nothing added context.
			name: "wrapped",
			err: fmt.Errorf("push index: %w", &transport.Error{
				StatusCode: http.StatusBadRequest,
				Errors:     []transport.Diagnostic{{Code: transport.ManifestBlobUnknownErrorCode}},
			}),
			want: true,
		},
		{name: "context canceled", err: context.Canceled, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMissingReference(tc.err); got != tc.want {
				t.Errorf("IsMissingReference(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
