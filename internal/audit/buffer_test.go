package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

type spyWriter struct {
	mu        sync.Mutex
	decisions []Decision
	err       error
}

func (s *spyWriter) WriteDecision(_ context.Context, d Decision) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions = append(s.decisions, d)
	return nil
}

func (s *spyWriter) WriteFindings(_ context.Context, _ Decision, _ []policy.Finding) error {
	return s.err
}

func (s *spyWriter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.decisions)
}

func TestRecordWritesAsync(t *testing.T) {
	w := &spyWriter{}
	a := NewAuditor(w, 16, func(Decision, error) {})
	defer a.Close()
	a.Record(context.Background(), Decision{PushID: "p1", Passed: true}, nil)
	a.Flush(context.Background())
	if w.count() != 1 {
		t.Errorf("decisions written = %d, want 1", w.count())
	}
}

func TestRecordNeverBlocksOnWriterError(t *testing.T) {
	w := &spyWriter{err: errors.New("clickhouse down")}
	dropped := make(chan error, 4)
	a := NewAuditor(w, 16, func(_ Decision, e error) { dropped <- e })
	defer a.Close()

	done := make(chan struct{})
	go func() {
		a.Record(context.Background(), Decision{PushID: "p1"}, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Record blocked on writer error")
	}
	a.Flush(context.Background())
	select {
	case <-dropped:
	case <-time.After(time.Second):
		t.Fatal("expected onDrop callback for failed write")
	}
}

// A dropped decision (write failure) must be reported WITH the decision, so an
// operator can identify which image's audit record was lost — silence here is how
// a passed-but-unrecorded scan became invisible in production.
func TestOnDropReceivesDecision(t *testing.T) {
	w := &spyWriter{err: errors.New("clickhouse down")}
	type drop struct {
		d   Decision
		err error
	}
	dropped := make(chan drop, 4)
	a := NewAuditor(w, 16, func(d Decision, e error) { dropped <- drop{d, e} })
	defer a.Close()

	a.Record(context.Background(), Decision{PushID: "p1", Repo: "c3.ai/c3-opensearch", Tag: "2.19.6-r3"}, nil)
	a.Flush(context.Background())

	select {
	case got := <-dropped:
		if got.d.Repo != "c3.ai/c3-opensearch" || got.d.Tag != "2.19.6-r3" {
			t.Errorf("onDrop got decision repo=%q tag=%q, want the recorded one", got.d.Repo, got.d.Tag)
		}
		if got.err == nil {
			t.Error("onDrop got nil error, want the write failure")
		}
	case <-time.After(time.Second):
		t.Fatal("expected onDrop callback for failed write")
	}
}

func TestRecordFlushConcurrentNoPanic(t *testing.T) {
	w := &spyWriter{}
	a := NewAuditor(w, 1000, func(Decision, error) {})
	defer a.Close()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				a.Record(context.Background(), Decision{PushID: "p"}, nil)
				a.Flush(context.Background())
			}
		}()
	}
	wg.Wait()
	// reaching here without panic is the assertion
}

func TestCloseIsIdempotent(t *testing.T) {
	a := NewAuditor(&spyWriter{}, 8, func(Decision, error) {})
	a.Record(context.Background(), Decision{PushID: "p"}, nil)
	a.Close()
	a.Close() // second close must not panic
}
