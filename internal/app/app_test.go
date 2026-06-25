package app

import (
	"testing"

	"github.com/merlin-gate/merlin/internal/config"
)

func minimalConfig() config.Config {
	return config.Config{
		Trivy:     config.TrivyConfig{SeverityThreshold: "CRITICAL"},
		BaseImage: config.BaseImageConfig{AllowedIDs: []string{"rhel", "wolfi", "chainguard"}},
		ACR:       config.ACRConfig{Registry: "myreg.azurecr.io"},
		Auth:      config.AuthConfig{Issuer: "https://issuer", Audience: "api://merlin"},
		Server:    config.ServerConfig{Addr: ":0", MetricsAddr: ":0"},
	}
}

func TestBuildWiresServers(t *testing.T) {
	main, metrics, err := Build(minimalConfig())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if main == nil || metrics == nil {
		t.Fatal("expected both servers wired")
	}
	if main.Handler == nil {
		t.Error("main server missing handler")
	}
}
