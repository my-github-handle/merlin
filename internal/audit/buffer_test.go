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

func (s *spyWriter) WriteFindings(_ context.Context, _ string, _ []policy.Finding) error {
	return s.err
}

func (s *spyWriter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.decisions)
}

func TestRecordWritesAsync(t *testing.T) {
	w := &spyWriter{}
	a := NewAuditor(w, 16, func(error) {})
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
	a := NewAuditor(w, 16, func(e error) { dropped <- e })
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

func TestRecordFlushConcurrentNoPanic(t *testing.T) {
	w := &spyWriter{}
	a := NewAuditor(w, 1000, func(error) {})
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
