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
func ClassifyPushError(err error) PushErrorClass {
	if err == nil {
		return PushErrNone
	}
	// Cancellation first: a canceled context often surfaces as a network error
	// further down the chain, and attributing a client disconnect or an expired
	// gate deadline to "network" would point at the wrong system.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return PushErrTimeout
	}
	// An HTTP response, even an error one, is more specific than the transport
	// error that may wrap it, so status wins over net.Error.
	var terr *transport.Error
	if errors.As(err, &terr) {
		switch terr.StatusCode {
		case 401, 403:
			return PushErrAuth
		case 404:
			return PushErrNotFound
		// Back-off signals are grouped with timeout: all three mean "retry later",
		// which is the only distinction an operator acts on here.
		case 408, 429, 504:
			return PushErrTimeout
		default:
			return PushErrOther
		}
	}
	// net.Error covers *net.OpError, *net.DNSError, *url.Error's inner net errors,
	// and bare syscall.Errno values (ECONNREFUSED and friends implement Timeout and
	// Temporary, so they satisfy the interface).
	var nerr net.Error
	if errors.As(err, &nerr) {
		// A net.Error that timed out is a timeout regardless of where it surfaced;
		// calling it "network" would hide slow-ACR incidents in the wrong bucket.
		if nerr.Timeout() {
			return PushErrTimeout
		}
		return PushErrNetwork
	}
	// ErrClosed is not itself a net.Error when it arrives unwrapped by net.
	if errors.Is(err, net.ErrClosed) {
		return PushErrNetwork
	}
	return PushErrOther
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
