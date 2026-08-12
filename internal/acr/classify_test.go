package acr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestClassifyPushError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want PushErrorClass
	}{
		{"nil", nil, PushErrNone},
		// PR 2431/2432: the 401 came from the second leg of ACR OAuth2. This is the
		// case the whole classification exists for — it must not read as "other".
		{"401 unauthorized", &transport.Error{StatusCode: 401}, PushErrAuth},
		{"403 forbidden", &transport.Error{StatusCode: 403}, PushErrAuth},
		{"404 not found", &transport.Error{StatusCode: 404}, PushErrNotFound},
		{"408 request timeout", &transport.Error{StatusCode: 408}, PushErrTimeout},
		{"429 too many requests", &transport.Error{StatusCode: 429}, PushErrTimeout},
		{"504 gateway timeout", &transport.Error{StatusCode: 504}, PushErrTimeout},
		{"400 bad request", &transport.Error{StatusCode: 400}, PushErrOther},
		{"500 server error", &transport.Error{StatusCode: 500}, PushErrOther},
		{"deadline exceeded", context.DeadlineExceeded, PushErrTimeout},
		{"canceled", context.Canceled, PushErrTimeout},
		{"connection refused", syscall.ECONNREFUSED, PushErrNetwork},
		{"dns failure", &net.DNSError{Err: "no such host", IsNotFound: true}, PushErrNetwork},
		{"opaque", errors.New("something odd"), PushErrOther},

		// Real errors arrive wrapped: the push path wraps with "acr push: %w" and
		// go-containerregistry wraps in *url.Error. Classification must unwrap, or it
		// degrades to "other" for every real failure.
		{"wrapped 401", fmt.Errorf("acr push: %w", &transport.Error{StatusCode: 401}), PushErrAuth},
		{
			"url.Error wrapping transport",
			&url.Error{Op: "Post", URL: "https://x", Err: &transport.Error{StatusCode: 403}},
			PushErrAuth,
		},
		{
			"url.Error wrapping dial",
			&url.Error{Op: "Post", URL: "https://x", Err: syscall.ECONNREFUSED},
			PushErrNetwork,
		},
		{
			"deeply wrapped deadline",
			fmt.Errorf("promote: %w", fmt.Errorf("acr push: %w", context.DeadlineExceeded)),
			PushErrTimeout,
		},
	}
	for _, tt := range tests {
		if got := ClassifyPushError(tt.err); got != tt.want {
			t.Errorf("%s: ClassifyPushError = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// The class set is a metric label value, so it must stay bounded and stable.
func TestClassifyPushErrorReturnsBoundedSet(t *testing.T) {
	allowed := map[PushErrorClass]bool{
		PushErrNone: true, PushErrAuth: true, PushErrNotFound: true,
		PushErrTimeout: true, PushErrNetwork: true, PushErrOther: true,
	}
	for _, err := range []error{
		nil, context.Canceled, syscall.ECONNRESET, errors.New("x"),
		&transport.Error{StatusCode: 401}, &transport.Error{StatusCode: 418},
	} {
		if got := ClassifyPushError(err); !allowed[got] {
			t.Errorf("ClassifyPushError(%v) = %q, which is outside the bounded label set", err, got)
		}
	}
}

func TestRegistryFromTarget(t *testing.T) {
	tests := []struct{ in, want string }{
		{"c3devops.azurecr.io/c3aiops:pr-2431", "c3devops.azurecr.io"},
		{"c3devops.azurecr.io/team/c3aiops@sha256:abc", "c3devops.azurecr.io"},
		{"c3devops.azurecr.io", "c3devops.azurecr.io"},
		{"localhost:5000/img:tag", "localhost:5000"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		if got := RegistryFromTarget(tt.in); got != tt.want {
			t.Errorf("RegistryFromTarget(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
