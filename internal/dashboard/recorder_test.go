package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
)

type spyRecorder struct{ called bool }

func (s *spyRecorder) Record(context.Context, audit.Decision, []policy.Finding) { s.called = true }

func TestTeeRecorderRecordsAndPublishes(t *testing.T) {
	spy := &spyRecorder{}
	b := NewBroadcaster(4)
	ch, cancel := b.Subscribe()
	defer cancel()
	tee := NewTeeRecorder(spy, b)

	tee.Record(context.Background(), audit.Decision{
		PushID: "p1", Repo: "a/b", Tag: "v1", Digest: "sha256:x", Identity: "ci",
		Passed: false, Reasons: []string{"CRITICAL"},
	}, nil)

	if !spy.called {
		t.Error("inner recorder was not called")
	}
	select {
	case d := <-ch:
		if d.Repo != "a/b" || d.Passed {
			t.Errorf("unexpected summary: %+v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("no summary published")
	}
}

func TestTeeRecorderNilInner(t *testing.T) {
	b := NewBroadcaster(4)
	ch, cancel := b.Subscribe()
	defer cancel()
	tee := NewTeeRecorder(nil, b) // nil inner must not panic; still publishes
	tee.Record(context.Background(), audit.Decision{Repo: "a/b"}, nil)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("no summary published with nil inner")
	}
}
