// Command merlin is the image-publishing gate proxy.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/merlin-gate/merlin/internal/app"
	"github.com/merlin-gate/merlin/internal/config"
	"github.com/merlin-gate/merlin/internal/limitexec"
)

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

	// Choose build mode: production (with live backends) or hermetic (for dev/test)
	mode := os.Getenv("MERLIN_MODE")
	var srv app.Servers

	if mode == "production" {
		log.Println("Starting in production mode with live backends...")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		srv, err = app.BuildWithBackends(ctx, cfg)
		if err != nil {
			log.Fatalf("build production: %v", err)
		}
		defer srv.Close()
	} else {
		log.Println("Starting in hermetic mode (dev/test)...")
		srv, err = app.Build(cfg)
		if err != nil {
			log.Fatalf("build hermetic: %v", err)
		}
	}

	// Drain budget for in-flight pushes on SIGTERM. Parsed before serving so a bad
	// value fails fast at startup rather than at shutdown.
	shutdownTimeout, err := time.ParseDuration(cfg.Server.ShutdownTimeout)
	if err != nil {
		log.Fatalf("parse shutdown_timeout %q: %v", cfg.Server.ShutdownTimeout, err)
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	// Start servers
	go func() {
		log.Printf("Metrics listening on %s", srv.Metrics.Addr)
		if err := srv.Metrics.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	go func() {
		log.Printf("Merlin listening on %s", srv.Gate.Addr)
		if err := srv.Gate.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("main server: %v", err)
		}
	}()

	if srv.Dashboard != nil {
		go func() {
			log.Printf("Dashboard listening on %s", srv.Dashboard.Addr)
			if err := srv.Dashboard.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("dashboard server: %v", err) // log, don't Fatal — never take down the gate
			}
		}()
	}

	<-done
	log.Printf("Shutting down gracefully (drain up to %s)...", shutdownTimeout)

	// Drain in-flight requests BEFORE closing backends: a layer upload or a manifest
	// PUT sitting in the gate keeps using Valkey/Blob/ACR, so cleanup() must run only
	// after Shutdown returns. Shutdown stops accepting new connections and waits for
	// active handlers to finish (or the timeout to elapse).
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := srv.Gate.Shutdown(shutdownCtx); err != nil {
		log.Printf("main server shutdown: %v", err)
	}
	if err := srv.Metrics.Shutdown(shutdownCtx); err != nil {
		log.Printf("metrics server shutdown: %v", err)
	}
	if srv.Dashboard != nil {
		if err := srv.Dashboard.Shutdown(shutdownCtx); err != nil {
			log.Printf("dashboard server shutdown: %v", err)
		}
	}

	srv.Close()
}
