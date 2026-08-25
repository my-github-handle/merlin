package dashboard

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
)

// The SSE endpoint had 0% coverage: handleStream, the noNewline framing writer and the
// subscriber teardown were all unexercised. It is the one route that holds a connection
// open for the life of an operator's browser tab, so its two failure modes are a wrong
// frame (the live feed silently stops updating) and a subscriber that is never removed
// (a slow leak in the gate's own process).
//
// NOTE ON SHAPE: these tests never call http.Get and then publish. handleStream sets its
// headers but does not Flush until the FIRST decision arrives, so net/http has not yet
// written the response head and a client blocks in Do() forever waiting for it. Every test
// below therefore publishes (or cancels) from another goroutine. That ordering constraint
// is the behaviour as it ships today, pinned here deliberately rather than fixed: this
// commit adds the net and changes no behaviour.

// sseTestServer returns a live server plus the broadcaster feeding it, because SSE cannot
// be tested through httptest.NewRecorder: the handler only returns when the request
// context ends, and reading the recorder while it writes is a data race.
func sseTestServer(t *testing.T) (*httptest.Server, *Broadcaster) {
	t.Helper()
	svc := newTestService(fakeReader{})
	rnd, err := NewRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	b := NewBroadcaster(4)
	srv := httptest.NewServer(NewServer(svc, rnd, b, func() time.Time { return time.Unix(1750000000, 0) }))
	t.Cleanup(srv.Close)
	return srv, b
}

// A published decision arrives as one `data: {...}` frame terminated by a single blank
// line. The framing is the contract with static/app.js: json.Encoder appends a newline of
// its own, which noNewline strips, and getting that wrong splits one event into two
// truncated ones that the browser drops without any error.
func TestStreamDeliversDecisionsAsSSEFrames(t *testing.T) {
	srv, b := sseTestServer(t)

	// Published from another goroutine: the response head does not arrive until the
	// handler's first Flush, which only happens once there is something to send.
	go publishOnceSubscribed(b, audit.DecisionSummary{
		PushID: "p1", Repo: "a/b", Tag: "v1", Digest: "sha256:x", Identity: "ci",
		Passed: false, Reasons: []string{"CRITICAL CVE-1"},
	})

	resp, err := http.Get(srv.URL + "/api/dashboard/stream")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache: a cached event stream never updates", cc)
	}

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !strings.HasPrefix(line, "data: ") {
		t.Fatalf("frame %q does not start with the SSE data prefix", line)
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(line, "data: "), "\n")
	if strings.Contains(payload, "\n") {
		t.Errorf("payload contains a newline, which ends the frame early: %q", payload)
	}
	// Lowercase keys are what app.js reads; PushID/Repo would render as blank rows.
	for _, want := range []string{`"push_id":"p1"`, `"repo":"a/b"`, `"passed":false`, `"CRITICAL CVE-1"`} {
		if !strings.Contains(payload, want) {
			t.Errorf("frame is missing %s:\n%s", want, payload)
		}
	}
}

// A disconnected browser must take its subscriber with it. Every tab subscribes on
// connect and Publish walks all subscribers on the gate's audit path, so a subscriber
// that outlives its request makes that walk longer for the rest of the process's life.
func TestStreamUnsubscribesWhenTheClientDisconnects(t *testing.T) {
	srv, b := sseTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/dashboard/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()

	waitForSubscribers(t, b, 1)
	cancel() // the browser closes the tab
	waitForSubscribers(t, b, 0)
	<-done
}

// A ResponseWriter that cannot flush is refused outright rather than buffering events
// until the connection dies — the operator would otherwise see an empty feed with a 200.
func TestStreamRefusesAWriterThatCannotFlush(t *testing.T) {
	svc := newTestService(fakeReader{})
	rnd, err := NewRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	s, ok := NewServer(svc, rnd, NewBroadcaster(4), nil).(*Server)
	if !ok {
		t.Fatal("NewServer no longer returns *Server; this test reaches the handler directly")
	}

	rec := httptest.NewRecorder()
	s.handleStream(unflushable{rec}, httptest.NewRequest("GET", "/api/dashboard/stream", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "streaming unsupported") {
		t.Errorf("body %q does not say why the stream was refused", rec.Body.String())
	}
	if s.b.SubscriberCount() != 0 {
		t.Error("a refused stream still registered a subscriber that nothing will ever remove")
	}
}

// unflushable hides httptest.ResponseRecorder's Flush method. Embedding the interface
// rather than the struct is what makes the type assertion in handleStream fail.
type unflushable struct{ http.ResponseWriter }

// publishOnceSubscribed waits for the handler to register, then sends. It reports nothing
// on timeout — it runs off the test goroutine, where t.Fatalf is illegal — and publishes
// anyway, so the failure surfaces as the reader's timeout instead.
func publishOnceSubscribed(b *Broadcaster, d audit.DecisionSummary) {
	for i := 0; i < 200 && b.SubscriberCount() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	b.Publish(d)
}

func waitForSubscribers(t *testing.T, b *Broadcaster, want int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if b.SubscriberCount() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("subscriber count = %d, want %d", b.SubscriberCount(), want)
}
