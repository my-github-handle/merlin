// Command merlin is the image-publishing gate proxy.
package main

import (
	"log"
	"os"

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
	mainSrv, metricsSrv, err := app.Build(cfg)
	if err != nil {
		log.Fatalf("build: %v", err)
	}
	go func() { log.Fatal(metricsSrv.ListenAndServe()) }()
	log.Printf("merlin listening on %s (metrics %s)", mainSrv.Addr, metricsSrv.Addr)
	log.Fatal(mainSrv.ListenAndServe())
}
