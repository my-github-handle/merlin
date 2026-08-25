package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/merlin-gate/merlin/internal/config"
)

// Builder constructs the servers Run will serve. BuildWithBackends satisfies it
// directly; Build needs a one-line adapter because it takes no context.
//
// It is a parameter rather than a mode string because the mode belongs to the process
// that read the environment, not to the lifecycle. Injecting it is also the only reason
// Run is testable: a test supplies servers bound to ephemeral ports and a Close it can
// count, with no ClickHouse, no Valkey and no ACR anywhere in the picture.
type Builder func(context.Context, config.Config) (Servers, error)

// Run builds the servers, serves them until ctx is done, drains in-flight requests
// within the configured budget, and only then releases the backends they hold.
//
// It returns nil for the ordinary lifecycle — ctx cancelled, drain complete — and an
// error only for a failure a caller should exit non-zero on: an unparsable drain
// budget, a failed build, or the gate/metrics listener dying. Draining and release
// happen on every one of those paths except the two that occur before anything is open.
//
// ctx is the SHUTDOWN SIGNAL, not a request context: cancelling it starts the drain. The
// signal wiring stays in main, so nothing here installs a handler on a shared,
// process-wide resource that a test would then have to undo.
func Run(ctx context.Context, cfg config.Config, build Builder) error {
	// Parsed BEFORE the build, so a bad value costs nothing. The old ordering opened
	// ClickHouse, Valkey, Blob and the JWKS refreshers first and only then discovered it
	// could not parse the drain budget — the failure the comment there claimed was
	// already fast.
	shutdownTimeout, err := time.ParseDuration(cfg.Server.ShutdownTimeout)
	if err != nil {
		return fmt.Errorf("parse shutdown_timeout %q: %w", cfg.Server.ShutdownTimeout, err)
	}

	srv, err := build(ctx, cfg)
	if err != nil {
		return err
	}
	// Deferred, and the ONLY release: every return below drains first, so the backends
	// outlive the last in-flight push either way. main used to call this twice — once
	// deferred at build, once at the end — which was harmless only because Auditor.Close
	// happens to be sync.Once-guarded.
	defer srv.Close()

	// Buffered for both fatal servers: a send must never block, or a gate that dies while
	// the metrics server is also dying would leak the goroutine past return.
	serveErr := make(chan error, 2)
	go serve("Metrics", "metrics server", srv.Metrics, serveErr)
	go serve("Merlin", "main server", srv.Gate, serveErr)

	// The dashboard NEVER takes down the gate. A bind failure there is logged and
	// dropped, which is the same rule that makes Servers.Dashboard nil-able at all.
	if srv.Dashboard != nil {
		go func() {
			log.Printf("Dashboard listening on %s", srv.Dashboard.Addr)
			if err := srv.Dashboard.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("dashboard server: %v", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
	case err = <-serveErr:
		// A listener died. Still drain: the other server may be mid-push, and the
		// backends are open either way. This used to be log.Fatalf inside the goroutine,
		// which skipped every defer and left the audit buffer unflushed.
	}

	log.Printf("Shutting down gracefully (drain up to %s)...", shutdownTimeout)
	drain(shutdownTimeout, srv)
	return err
}

// serve starts one of the two servers whose death is fatal to the process. logName is
// the startup line's subject ("Merlin listening on :5000"); errName prefixes the
// failure, and both spellings are the ones the deployment's log-based alerts match on.
func serve(logName, errName string, s *http.Server, errCh chan<- error) {
	log.Printf("%s listening on %s", logName, s.Addr)
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		errCh <- fmt.Errorf("%s: %w", errName, err)
	}
}

// drain stops accepting connections and waits for active handlers, up to budget.
//
// The budget hangs off context.Background(), NOT off the context that just ended: Run is
// woken by that context being cancelled, so deriving from it would give every Shutdown a
// deadline that has already passed — an instant kill of exactly the in-flight layer
// uploads and manifest PUTs the budget exists to protect.
func drain(budget time.Duration, srv Servers) {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	// Gate first: it is the one holding pushes that are still using Valkey, Blob and ACR.
	if err := srv.Gate.Shutdown(ctx); err != nil {
		log.Printf("main server shutdown: %v", err)
	}
	if err := srv.Metrics.Shutdown(ctx); err != nil {
		log.Printf("metrics server shutdown: %v", err)
	}
	if srv.Dashboard != nil {
		if err := srv.Dashboard.Shutdown(ctx); err != nil {
			log.Printf("dashboard server shutdown: %v", err)
		}
	}
}
