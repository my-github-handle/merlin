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

// aliasSpy is a recorder that DOES support tag aliases, as audit.Auditor does.
type aliasSpy struct {
	spyRecorder
	aliases []audit.TagAlias
}

func (a *aliasSpy) RecordTagAlias(_ context.Context, alias audit.TagAlias) {
	a.aliases = append(a.aliases, alias)
}

// TeeRecorder must keep satisfying the interface the docker ingress type-asserts
// (internal/ingress/docker/manifest.go:167). This is a compile-time assertion because the
// failure mode is silent: h.tagAliasRecorder() would simply report !ok and every buildx
// tag alias would be dropped with no error anywhere.
var _ interface {
	RecordTagAlias(context.Context, audit.TagAlias)
} = (*TeeRecorder)(nil)

// The pass-through the comment on RecordTagAlias exists for: wrapping the auditor must not
// cost tag aliases, because report-by-tag lookups for buildx pushes resolve through them.
func TestTeeRecorderForwardsTagAliasesToAnAuditorThatTakesThem(t *testing.T) {
	spy := &aliasSpy{}
	tee := NewTeeRecorder(spy, NewBroadcaster(4))

	alias := audit.TagAlias{Repo: "a/b", Tag: "v1", Digest: "sha256:x"}
	tee.RecordTagAlias(context.Background(), alias)

	if len(spy.aliases) != 1 {
		t.Fatalf("inner recorder got %d aliases, want 1: by-tag report lookup is now blind", len(spy.aliases))
	}
	if spy.aliases[0] != alias {
		t.Errorf("alias = %+v, want %+v", spy.aliases[0], alias)
	}
}

// An inner recorder without alias support, and no inner recorder at all, are both dropped
// silently rather than panicking: an alias is best-effort (manifest.go:72), and a panic
// here would take down a push that had already passed the gate.
func TestTeeRecorderDropsTagAliasWhenTheInnerCannotTakeIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		inner DecisionRecorder
	}{
		{name: "inner without alias support", inner: &spyRecorder{}},
		{name: "no inner at all", inner: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tee := NewTeeRecorder(tc.inner, NewBroadcaster(4))
			tee.RecordTagAlias(context.Background(), audit.TagAlias{Repo: "a/b", Tag: "v1"})
		})
	}
}

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

func TestTeeRecorderNilBroadcaster(t *testing.T) {
	spy := &spyRecorder{}
	tee := NewTeeRecorder(spy, nil) // non-nil inner, nil broadcaster must not panic
	tee.Record(context.Background(), audit.Decision{
		PushID: "p1", Repo: "a/b", Tag: "v1", Digest: "sha256:x", Identity: "ci",
		Passed: false, Reasons: []string{"CRITICAL"},
	}, nil)

	if !spy.called {
		t.Error("inner recorder was not called")
	}
}
