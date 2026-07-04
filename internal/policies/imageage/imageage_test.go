package imageage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

func fixedNow() time.Time { return time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC) }

func newTestPolicy(def Rule, per map[string]Rule) *Policy {
	p := New(def, per)
	p.now = fixedNow // deterministic
	return p
}

func TestFreshImagePasses(t *testing.T) {
	p := newTestPolicy(Rule{Enabled: true, ThresholdDays: 60}, nil)
	v, err := p.Evaluate(context.Background(), policy.StagedImage{
		Created: fixedNow().Add(-10 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !v.Passed || v.Age == nil || !v.Age.Compliant || v.Age.AgeDays != 10 {
		t.Fatalf("expected compliant pass, got passed=%v age=%+v", v.Passed, v.Age)
	}
}

func TestOldImageRejected(t *testing.T) {
	p := newTestPolicy(Rule{Enabled: true, ThresholdDays: 60}, nil)
	created := fixedNow().Add(-74 * 24 * time.Hour)
	v, err := p.Evaluate(context.Background(), policy.StagedImage{Created: created})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Passed {
		t.Fatal("expected reject for 74-day-old image")
	}
	if v.Age == nil || v.Age.Compliant || v.Age.AgeDays != 74 || v.Age.ThresholdDays != 60 {
		t.Fatalf("age info wrong: %+v", v.Age)
	}
	if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "age 74d exceeds max 60d") {
		t.Fatalf("reason wrong: %v", v.Reasons)
	}
}

func TestBoundaryEqualsThresholdPasses(t *testing.T) {
	p := newTestPolicy(Rule{Enabled: true, ThresholdDays: 60}, nil)
	v, _ := p.Evaluate(context.Background(), policy.StagedImage{
		Created: fixedNow().Add(-60 * 24 * time.Hour),
	})
	if !v.Passed {
		t.Fatal("age == threshold must pass (<=)")
	}
}

func TestUnknownCreatedFailsClosed(t *testing.T) {
	p := newTestPolicy(Rule{Enabled: true, ThresholdDays: 60}, nil)
	v, err := p.Evaluate(context.Background(), policy.StagedImage{}) // zero Created
	if err != nil {
		t.Fatalf("Evaluate must not return infra error for unknown age: %v", err)
	}
	if v.Passed {
		t.Fatal("unknown created must fail closed")
	}
	if v.Age == nil || v.Age.Known {
		t.Fatalf("expected Age.Known=false, got %+v", v.Age)
	}
	if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "could not determine image age") {
		t.Fatalf("expected distinct unknown-age reason, got %v", v.Reasons)
	}
	if strings.Contains(v.Reasons[0], "exceeds max") {
		t.Fatal("unknown-age reason must not read like a too-old verdict")
	}
}

func TestDisabledTenantSkipsGating(t *testing.T) {
	p := newTestPolicy(
		Rule{Enabled: true, ThresholdDays: 60},
		map[string]Rule{"slowmirror": {Enabled: false}},
	)
	// A very old image under a disabled tenant passes and reports no age.
	v, _ := p.Evaluate(context.Background(), policy.StagedImage{
		Prefix:  "slowmirror",
		Created: fixedNow().Add(-999 * 24 * time.Hour),
	})
	if !v.Passed {
		t.Fatal("disabled tenant must not gate on age")
	}
	if v.Age != nil {
		t.Fatalf("disabled tenant must report no age, got %+v", v.Age)
	}
}

func TestPerTenantThresholdOverride(t *testing.T) {
	p := newTestPolicy(
		Rule{Enabled: true, ThresholdDays: 60},
		map[string]Rule{"vendor": {Enabled: true, ThresholdDays: 365}},
	)
	v, _ := p.Evaluate(context.Background(), policy.StagedImage{
		Prefix:  "vendor",
		Created: fixedNow().Add(-200 * 24 * time.Hour),
	})
	if !v.Passed {
		t.Fatal("200d image under 365d tenant threshold must pass")
	}
	if v.Age.ThresholdDays != 365 {
		t.Fatalf("expected threshold 365, got %d", v.Age.ThresholdDays)
	}
}
