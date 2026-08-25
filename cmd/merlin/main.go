// Command merlin is the image-publishing gate proxy.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/merlin-gate/merlin/internal/app"
	"github.com/merlin-gate/merlin/internal/config"
	"github.com/merlin-gate/merlin/internal/limitexec"
)

// main resolves the environment, installs the signal handler, and turns an error into an
// exit code. The lifecycle it used to inline — serve, drain, release — is app.Run, which
// is reachable from a test; this function is not, so nothing that can fail in an
// interesting way should live here.
func main() {
	// Memory-bounding trampoline for child processes (grype). Handled before
	// anything else: this process exists only to set a resource limit and exec
	// the child, so it must not load config or open backends.
	if len(os.Args) > 1 && os.Args[1] == limitexec.Flag {
		// Only reached on failure — a successful Exec replaces this process.
		log.Fatalf("limited-exec: %v", limitexec.Main(os.Args[2:]))
	}

	path := os.Getenv("MERLIN_CONFIG")
	if path == "" {
		path = "config.yaml"
	}
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// SIGTERM is how Kubernetes starts a rollout, so it is the drain trigger rather than
	// an abort. NotifyContext rather than a channel: the same cancellation then bounds the
	// build's own goroutines (JWKS refreshers, promotion worker, samplers).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, cfg, builder(os.Getenv("MERLIN_MODE"))); err != nil {
		log.Fatalf("%v", err)
	}
}

// builder picks the build mode and owns every string that names it: the startup line and
// the error prefix. app.Run takes the closure and knows nothing about modes, which is why
// adding one cannot change the lifecycle.
//
// Anything other than "production" is hermetic — a deployment that misspells the mode
// gets the stub-auth build that rejects every token, which is the fail-closed direction.
func builder(mode string) app.Builder {
	if mode == "production" {
		return func(ctx context.Context, cfg config.Config) (app.Servers, error) {
			log.Println("Starting in production mode with live backends...")
			srv, err := app.BuildWithBackends(ctx, cfg)
			if err != nil {
				return app.Servers{}, fmt.Errorf("build production: %w", err)
			}
			return srv, nil
		}
	}
	return func(_ context.Context, cfg config.Config) (app.Servers, error) {
		log.Println("Starting in hermetic mode (dev/test)...")
		srv, err := app.Build(cfg)
		if err != nil {
			return app.Servers{}, fmt.Errorf("build hermetic: %w", err)
		}
		return srv, nil
	}
}
