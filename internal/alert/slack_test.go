package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const fakeSecretPath = "/services/T00000000/B00000000/XXXXsupersecrettokenXXXX"

var sampleFinding = Finding{
	Detector:  DetectorNovelError,
	Signature: "staging: CROSSSLOT keys do not hash to the same slot",
	Summary:   "new failure signature, 2 occurrence(s): staging: CROSSSLOT keys do not hash to the same slot",
	Count:     2,
	Evidence:  "staging: valkey eval: CROSSSLOT keys do not hash to the same slot (push 6f0d5c4b-3a29-4d18-9e07-1f2a3b4c5d6e)",
	FirstSeen: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC),
	LastSeen:  time.Date(2026, 8, 11, 9, 42, 0, 0, time.UTC),
}

func TestSlackPostsTheFinding(t *testing.T) {
	var gotBody []byte
	var gotType, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	s := NewSlack(srv.URL, "merlin-opsadmin")
	if err := s.Notify(context.Background(), sampleFinding); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if !strings.Contains(gotType, "application/json") {
		t.Errorf("content-type = %q", gotType)
	}
	var payload struct{ Text string }
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("body is not the JSON Slack expects: %v (%s)", err, gotBody)
	}
	// Everything an operator needs to act without opening a terminal first, plus the
	// environment name — one channel usually receives more than one deployment.
	for _, want := range []string{
		"merlin-opsadmin",
		DetectorNovelError,
		"CROSSSLOT",
		"2",
		"2026-08-11T09:42:00Z",
	} {
		if !strings.Contains(payload.Text, want) {
			t.Errorf("message is missing %q:\n%s", want, payload.Text)
		}
	}
}

func TestSlackReportsHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "invalid_payload")
	}))
	defer srv.Close()

	s := NewSlack(srv.URL, "env")
	err := s.Notify(context.Background(), sampleFinding)
	if err == nil {
		t.Fatal("a 500 from Slack must be an error, or the runner records a cooldown for a message nobody received")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should name the status: %v", err)
	}
}

func TestSlackNeverLeaksTheWebhookURL(t *testing.T) {
	// The webhook URL IS the credential: anyone holding it can post to the channel.
	// Go's own http errors embed the URL, so the error has to be rewritten, not wrapped.
	s := NewSlack("http://127.0.0.1:1"+fakeSecretPath, "env")
	err := s.Notify(context.Background(), sampleFinding)
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "supersecrettoken") || strings.Contains(err.Error(), fakeSecretPath) {
		t.Errorf("webhook URL leaked into the error: %v", err)
	}
}

func TestSlackHonoursContextCancel(t *testing.T) {
	// The handler sleeps a bounded time rather than waiting on r.Context(): a
	// client-side timeout does not reliably cancel the server's request context, so
	// waiting on it would hang srv.Close() instead of testing anything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s := NewSlack(srv.URL, "env")
	if err := s.Notify(ctx, sampleFinding); err == nil {
		t.Error("expected a context error")
	}
}

func TestSlackTruncatesEvidence(t *testing.T) {
	// grype stderr can be kilobytes. Slack rejects oversized payloads, and the
	// rejection would be indistinguishable from "no alerts fired".
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	f := sampleFinding
	f.Evidence = strings.Repeat("stderr line that goes on and on; ", 400)
	if err := NewSlack(srv.URL, "env").Notify(context.Background(), f); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if len(body) > maxSlackBody {
		t.Errorf("payload is %d bytes, cap is %d", len(body), maxSlackBody)
	}
}
