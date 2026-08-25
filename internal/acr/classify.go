package acr

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// PushErrorClass is a coarse, bounded cause for a failed ACR push. It exists to
// be a metric label: "the push failed" is not actionable, but "the push to THIS
// registry failed on auth" names the owner of the fix. On PR 2431 a tenant's
// workload identity lost AcrPush and the only signal was an unlabelled error
// counter, so the 401 was indistinguishable from a network blip for two days.
//
// The set is deliberately small and closed. Anything derived from an error
// *string* would be unbounded cardinality, so classification is by type and
// status code only.
type PushErrorClass string

const (
	PushErrNone     PushErrorClass = "ok"        // no error
	PushErrAuth     PushErrorClass = "auth"      // HTTP 401, 403 — identity/RBAC
	PushErrNotFound PushErrorClass = "not_found" // HTTP 404 — repo/registry missing
	PushErrTimeout  PushErrorClass = "timeout"   // deadline, 408, 429, 504 — retryable
	PushErrNetwork  PushErrorClass = "network"   // dial/DNS/reset — no HTTP response
	PushErrOther    PushErrorClass = "other"     // everything else
)

// ClassifyPushError maps a push error to its class. Real errors arrive wrapped
// several layers deep ("acr push: %w" over *url.Error over *transport.Error), so
// every check unwraps via errors.As/errors.Is rather than inspecting the top
// error.
//
// The body is nothing but the ORDER, because the order is what carries the meaning. A
// real push error satisfies several of these at once — *url.Error implements
// Timeout()/Temporary() and so is itself a net.Error, whatever it wraps — and the line
// that claims it decides which system an operator is sent to look at. Each recogniser
// is one line here and explains itself where it is defined.
//
// TestClassifyPushErrorPrecedence pins every step: each case there returns a different
// class if its line moves.
func ClassifyPushError(err error) PushErrorClass {
	if err == nil {
		return PushErrNone
	}
	// 1. Cancellation, ahead of everything: it resurfaces below as a network error, and
	//    a client disconnect reported as "network" accuses ACR of the client's doing.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return PushErrTimeout
	}
	// 2. An HTTP status, ahead of net.Error: a status means ACR answered, which is
	//    strictly more specific than the transport error carrying the answer.
	var terr *transport.Error
	if errors.As(err, &terr) {
		return classifyStatus(terr.StatusCode)
	}
	// 3. No response at all.
	var nerr net.Error
	if errors.As(err, &nerr) {
		return classifyNetError(nerr)
	}
	// 4. A closed connection that is not a net.Error. Nothing in the standard library
	//    has that shape — net.ErrClosed is poll.errNetClosing, which has Timeout() and
	//    Temporary() and is therefore already claimed by step 3, bare or wrapped. This
	//    step survives for a third-party error that reports Is(net.ErrClosed) without
	//    satisfying the interface; see TestClassifyPushErrorCatchesAClosedErrorThatIsNotANetError,
	//    which has to synthesise one to reach it.
	if errors.Is(err, net.ErrClosed) {
		return PushErrNetwork
	}
	return PushErrOther
}

// classifyStatus maps an ACR HTTP status to its class. This is the one genuine
// (matcher -> class) table in the chain: a closed set of codes, each naming who fixes it.
//
// Unlisted codes are "other" rather than a guess. The class is a metric label an operator
// routes on, so inventing a plausible bucket for an unrecognised status hides it inside a
// cause that already has an owner.
func classifyStatus(code int) PushErrorClass {
	switch code {
	case 401, 403:
		return PushErrAuth // identity/RBAC — the PR 2431 case this classification exists for
	case 404:
		return PushErrNotFound // repo or registry missing
	case 408, 429, 504:
		// Back-off signals group with timeout: all three mean "retry later", which is
		// the only distinction an operator acts on here.
		return PushErrTimeout
	default:
		return PushErrOther
	}
}

// classifyNetError splits a failure that never got an HTTP response into "too slow" and
// "could not connect".
//
// net.Error covers *net.OpError, *net.DNSError, *url.Error's inner net errors, and bare
// syscall.Errno values (ECONNREFUSED and friends implement Timeout and Temporary, so they
// satisfy the interface). A timed-out one is a timeout wherever it surfaced: reporting it
// as "network" would file slow-ACR incidents under connectivity, which is a different
// on-call and a different fix.
func classifyNetError(nerr net.Error) PushErrorClass {
	if nerr.Timeout() {
		return PushErrTimeout
	}
	return PushErrNetwork
}

// RegistryFromTarget extracts the registry host from a push target
// ("c3devops.azurecr.io/c3aiops:tag" -> "c3devops.azurecr.io"). The host is the
// metric label, so an empty target yields the literal "unknown" rather than an
// empty label value, which reads as a scrape gap on a dashboard.
func RegistryFromTarget(target string) string {
	if target == "" {
		return "unknown"
	}
	if host, _, ok := strings.Cut(target, "/"); ok {
		return host
	}
	return target
}
