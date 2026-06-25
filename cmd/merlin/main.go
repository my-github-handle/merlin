// Command merlin is the image-publishing gate proxy.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/merlin-gate/merlin/internal/app"
	"github.com/merlin-gate/merlin/internal/config"
)

func main() {
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
	var mainSrv, metricsSrv *http.Server
	var cleanup func()

	if mode == "production" {
		log.Println("Starting in production mode with live backends...")
		mainSrv, metricsSrv, cleanup, err = app.BuildWithBackends(context.Background(), cfg)
		if err != nil {
			log.Fatalf("build production: %v", err)
		}
		defer cleanup()
	} else {
		log.Println("Starting in hermetic mode (dev/test)...")
		mainSrv, metricsSrv, err = app.Build(cfg)
		if err != nil {
			log.Fatalf("build hermetic: %v", err)
		}
		cleanup = func() {}
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	// Start both servers
	go func() {
		log.Printf("Metrics listening on %s", metricsSrv.Addr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	go func() {
		log.Printf("Merlin listening on %s", mainSrv.Addr)
		if err := mainSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("main server: %v", err)
		}
	}()

	<-done
	log.Println("Shutting down gracefully...")
	cleanup()
}
