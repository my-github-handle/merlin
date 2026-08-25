package acr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
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

// ClassifyPushError is an ORDERED chain, and the order is the part that carries meaning:
// several of these errors match more than one arm, and which arm wins decides which system
// an operator goes and looks at. Each case below produces a DIFFERENT class if its arm is
// moved, so these pin the order rather than just the mapping.
func TestClassifyPushErrorPrecedence(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want PushErrorClass
		why  string
	}{
		{
			// *url.Error implements Timeout()/Temporary(), so it satisfies net.Error itself.
			// Every wrapped error below is therefore matched by the net.Error arm too.
			name: "cancellation beats net.Error",
			err:  &url.Error{Op: "Post", URL: "https://x", Err: context.Canceled},
			want: PushErrTimeout,
			why:  "classified as network, an abandoned push looks like an ACR outage",
		},
		{
			name: "http status beats net.Error",
			err:  &url.Error{Op: "Post", URL: "https://x", Err: &transport.Error{StatusCode: 500}},
			want: PushErrOther,
			why:  "ACR answered; calling it network points at the wrong system",
		},
		{
			name: "auth status beats net.Error",
			err:  &url.Error{Op: "Post", URL: "https://x", Err: &transport.Error{StatusCode: 401}},
			want: PushErrAuth,
			why:  "this is the PR 2431 shape: a 401 inside a url.Error must stay auth",
		},
		{
			// The one branch inside the net.Error arm: timed-out net errors are timeouts, so
			// a slow ACR does not hide in the network bucket.
			name: "net.Error that timed out",
			err:  &net.DNSError{Err: "i/o timeout", IsTimeout: true},
			want: PushErrTimeout,
			why:  "a slow resolver is a timeout, not a connectivity failure",
		},
		{
			name: "os deadline exceeded is a timing-out net.Error",
			err:  fmt.Errorf("read blob: %w", os.ErrDeadlineExceeded),
			want: PushErrTimeout,
			why:  "a socket deadline is the same incident as a gate deadline",
		},
		{
			name: "net.Error that did not time out",
			err:  &net.DNSError{Err: "no such host", IsNotFound: true},
			want: PushErrNetwork,
			why:  "an unresolvable host is connectivity, not slowness",
		},
		{
			name: "closed connection",
			err:  fmt.Errorf("write blob: %w", net.ErrClosed),
			want: PushErrNetwork,
			why:  "a torn-down connection is connectivity",
		},
	}
	for _, tt := range tests {
		if got := ClassifyPushError(tt.err); got != tt.want {
			t.Errorf("%s: ClassifyPushError = %q, want %q — %s", tt.name, got, tt.want, tt.why)
		}
	}
}

// isClosedOnly reports Is(net.ErrClosed) without satisfying net.Error. Nothing in the
// standard library has this shape — net.ErrClosed is poll.errNetClosing, which has
// Timeout() and Temporary() and so is matched by the net.Error arm before the ErrClosed
// check is ever reached. This type is the only way to reach that check, which is the
// evidence that it is otherwise unreachable; it is kept because removing it would change
// behaviour for exactly this shape.
type isClosedOnly struct{}

func (isClosedOnly) Error() string        { return "conn closed by peer" }
func (isClosedOnly) Is(target error) bool { return target == net.ErrClosed }

func TestClassifyPushErrorCatchesAClosedErrorThatIsNotANetError(t *testing.T) {
	var nerr net.Error
	if errors.As(error(isClosedOnly{}), &nerr) {
		t.Fatal("isClosedOnly satisfies net.Error, so it no longer reaches the ErrClosed arm")
	}
	if got := ClassifyPushError(isClosedOnly{}); got != PushErrNetwork {
		t.Errorf("ClassifyPushError = %q, want %q", got, PushErrNetwork)
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
