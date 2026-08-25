package app

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/config"
)

// The startup path had NO test before app.Run existed: it was a 99-line main, and
// `go test` reported cmd/merlin at 0.0% because there is nothing there to call. These
// tests exist to cover the part that can actually go wrong in production — the drain —
// without a single live backend.

// runFixture is a build whose servers bind ephemeral ports and whose Close is countable.
type runFixture struct {
	mu     sync.Mutex
	events []string // ordered record of what happened, for the drain-ordering assertions

	gate    *http.Server
	metrics *http.Server
	dash    *http.Server

	startedSlow chan struct{} // signalled once the /slow handler is executing
	builds      int
}

func (f *runFixture) record(event string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *runFixture) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *runFixture) closes() int {
	n := 0
	for _, e := range f.log() {
		if e == "close" {
			n++
		}
	}
	return n
}

func (f *runFixture) build(_ context.Context, _ config.Config) (Servers, error) {
	f.builds++
	return Servers{
		Gate:      f.gate,
		Metrics:   f.metrics,
		Dashboard: f.dash,
		Close:     func() { f.record("close") },
	}, nil
}

// newRunFixture wires a gate with two routes — /ready for readiness polling and /slow for
// a handler that is still running when the drain begins — plus a metrics server.
// The returned release func unblocks /slow and is safe to call more than once, so a test
// that releases explicitly and the cleanup that releases unconditionally can coexist.
func newRunFixture(t *testing.T) (*runFixture, func()) {
	t.Helper()
	releaseCh := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(releaseCh) }) }
	started := make(chan struct{}, 1)
	f := &runFixture{}

	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/slow", func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-releaseCh
		f.record("handler done")
		w.WriteHeader(http.StatusOK)
	})

	f.gate = &http.Server{Addr: freeAddr(t), Handler: mux}
	f.metrics = &http.Server{Addr: freeAddr(t), Handler: http.NewServeMux()}
	t.Cleanup(func() {
		release()
		_ = f.gate.Close()
		_ = f.metrics.Close()
		if f.dash != nil {
			_ = f.dash.Close()
		}
	})
	f.startedSlow = started
	return f, release
}

// freeAddr reserves an ephemeral port and releases it, so the caller can hand the address
// to an http.Server that binds it itself. ListenAndServe owns its listener, which is why
// the port cannot simply be passed in.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return addr
}

// waitReady polls until the gate answers, so a test never races the listener.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		resp, err := http.Get("http://" + addr + "/ready")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("gate never accepted a connection on %s", addr)
}

// quietLogs silences Run's startup and shutdown lines for the duration of one test.
func quietLogs(t *testing.T) {
	t.Helper()
	out := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(out) })
}

func cfgWithDrain(budget string) config.Config {
	var cfg config.Config
	cfg.Server.ShutdownTimeout = budget
	return cfg
}

// The ordinary lifecycle: serve until cancelled, then drain and release exactly once.
func TestRunServesUntilCancelledThenReleasesOnce(t *testing.T) {
	quietLogs(t)
	f, _ := newRunFixture(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfgWithDrain("30s"), f.build) }()
	waitReady(t, f.gate.Addr)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v, want nil for an ordinary shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of cancellation")
	}
	if n := f.closes(); n != 1 {
		t.Errorf("Close ran %d times, want exactly 1", n)
	}
}

// The drain budget is parsed BEFORE anything is built.
//
// This is the one deliberate behaviour change in the extraction. main parsed it after the
// build, so `shutdown_timeout: banana` opened ClickHouse, Valkey, Blob and every JWKS
// refresher, then died on a string it could have rejected for free — and died via
// log.Fatalf, so none of them were released.
func TestRunRejectsBadDrainBudgetBeforeBuilding(t *testing.T) {
	quietLogs(t)
	f, _ := newRunFixture(t)

	err := Run(context.Background(), cfgWithDrain("banana"), f.build)
	if err == nil {
		t.Fatal("Run accepted an unparsable shutdown_timeout")
	}
	if !strings.Contains(err.Error(), "shutdown_timeout") || !strings.Contains(err.Error(), "banana") {
		t.Errorf("error %q names neither the field nor the value an operator has to fix", err)
	}
	if f.builds != 0 {
		t.Errorf("builder ran %d times: backends were opened before the config was known to be usable", f.builds)
	}
}

// A failed build is returned verbatim, so main's exit message is the builder's.
func TestRunReturnsBuildErrorUnwrapped(t *testing.T) {
	quietLogs(t)
	sentinel := errors.New("build production: audit writer: dial tcp: refused")

	err := Run(context.Background(), cfgWithDrain("30s"),
		func(context.Context, config.Config) (Servers, error) { return Servers{}, sentinel })

	if !errors.Is(err, sentinel) {
		t.Fatalf("Run() = %v, want the build error itself", err)
	}
}

// A push still running when SIGTERM arrives finishes, and the backends it is using are
// released only afterwards.
//
// The bug this pins is a one-word one: deriving the drain context from the context that
// just woke Run. That context is ALREADY cancelled, so every Shutdown would return
// instantly, the layer upload below would be cut mid-flight, and Close would free the
// blob client and the audit buffer underneath it. Nothing about the code's shape reveals
// which context was used — only this test does.
func TestRunDrainsInFlightPushBeforeReleasingBackends(t *testing.T) {
	quietLogs(t)
	f, release := newRunFixture(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfgWithDrain("30s"), f.build) }()
	waitReady(t, f.gate.Addr)

	// A request that is mid-handler when the drain starts.
	status := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + f.gate.Addr + "/slow")
		if err != nil {
			status <- -1
			return
		}
		defer resp.Body.Close()
		status <- resp.StatusCode
	}()
	select {
	case <-f.startedSlow:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow handler never started")
	}

	cancel()
	// Give the drain a moment to reach Shutdown and (wrongly) give up on the handler.
	time.Sleep(200 * time.Millisecond)
	if n := f.closes(); n != 0 {
		t.Fatalf("Close ran while a push was still in flight (%d times)", n)
	}

	release()
	if got := <-status; got != http.StatusOK {
		t.Errorf("in-flight request finished with %d, want 200: the drain budget did not protect it", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	if got := f.log(); len(got) != 2 || got[0] != "handler done" || got[1] != "close" {
		t.Errorf("event order = %v, want [handler done, close]", got)
	}
}

// A dead gate listener is returned as an error rather than killing the process from
// inside a goroutine — and the backends are still released on the way out.
func TestRunSurfacesFatalServeErrorAndStillReleases(t *testing.T) {
	quietLogs(t)
	f, _ := newRunFixture(t)

	// Occupy the gate's port so ListenAndServe fails immediately.
	blocker, err := net.Listen("tcp", f.gate.Addr)
	if err != nil {
		t.Fatalf("occupy gate port: %v", err)
	}
	defer blocker.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(context.Background(), cfgWithDrain("30s"), f.build) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Run() = nil though the gate could not bind")
		}
		if !strings.Contains(err.Error(), "main server") {
			t.Errorf("error %q does not identify which server died", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run hung after the gate listener died")
	}
	if n := f.closes(); n != 1 {
		t.Errorf("Close ran %d times, want 1: log.Fatalf used to skip release entirely", n)
	}
}

// The dashboard never takes down the gate, whether it is absent or merely broken.
func TestRunKeepsTheGateWhenTheDashboardDoesNot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		unbound bool // give the dashboard a port that is already taken
	}{
		{name: "no dashboard at all"},
		{name: "dashboard cannot bind", unbound: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			quietLogs(t)
			f, _ := newRunFixture(t)
			if tc.unbound {
				// An UNRELATED holder of the port, not the metrics server's address: the
				// two would race to bind it and the loser might be the one whose death is
				// fatal, which would test the opposite of the intent.
				blocker, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("occupy a port for the dashboard to fail on: %v", err)
				}
				defer blocker.Close()
				f.dash = &http.Server{Addr: blocker.Addr().String(), Handler: http.NewServeMux()}
			}
			ctx, cancel := context.WithCancel(context.Background())

			done := make(chan error, 1)
			go func() { done <- Run(ctx, cfgWithDrain("30s"), f.build) }()
			waitReady(t, f.gate.Addr)

			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run() = %v, want nil: the dashboard must never fail the gate", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return within 10s of cancellation")
			}
		})
	}
}
