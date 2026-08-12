package alert

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)

func detail(d string, n uint64) DetailCount {
	return DetailCount{Detail: d, Count: n, First: t0, Last: t0.Add(time.Minute)}
}

func TestNovelErrorsFiresOnlyForUnseenSignatures(t *testing.T) {
	baseline := []DetailCount{
		detail("run grype: signal: killed", 240),
		detail("acr push: unexpected status 401", 12),
	}
	recent := []DetailCount{
		// Same cause as the baseline's first row, different image: NOT novel.
		detail("run grype: signal: killed", 3),
		// Same 401 cause, different registry URL in the message: NOT novel.
		detail("acr push: unexpected status 401", 1),
		// Genuinely new.
		detail("staging: valkey: CROSSSLOT keys do not hash to the same slot", 2),
	}
	got, dropped := NovelErrors(recent, baseline, 10)
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].Detector != DetectorNovelError {
		t.Errorf("detector = %q", got[0].Detector)
	}
	if !strings.Contains(got[0].Signature, "CROSSSLOT") {
		t.Errorf("signature = %q, want the CROSSSLOT error", got[0].Signature)
	}
	if got[0].Count != 2 {
		t.Errorf("count = %d, want 2", got[0].Count)
	}
}

func TestNovelErrorsGroupsSameSignatureIntoOneFinding(t *testing.T) {
	// Three pushes, three distinct error_detail strings, one cause. Ungrouped this
	// would be three Slack messages for one problem.
	recent := []DetailCount{
		detail("assemble: open /tmp/merlin/merlin-assemble-111/blobs: no such file or directory", 1),
		detail("assemble: open /tmp/merlin/merlin-assemble-222/blobs: no such file or directory", 4),
		detail("assemble: open /tmp/merlin/merlin-assemble-333/blobs: no such file or directory", 2),
	}
	got, _ := NovelErrors(recent, nil, 10)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].Count != 7 {
		t.Errorf("count = %d, want 7 (1+4+2)", got[0].Count)
	}
}

func TestNovelErrorsCapReportsWhatItDropped(t *testing.T) {
	// A silent cap reads as "that was everything". If the run is truncated the caller
	// has to be able to say so.
	var recent []DetailCount
	for _, s := range []string{"alpha", "bravo", "charlie", "delta", "echo"} {
		recent = append(recent, detail("brand new failure "+s, 1))
	}
	got, dropped := NovelErrors(recent, nil, 2)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if dropped != 3 {
		t.Errorf("dropped = %d, want 3", dropped)
	}
}

func TestNovelErrorsRanksByCount(t *testing.T) {
	recent := []DetailCount{
		detail("rare new failure", 1),
		detail("common new failure", 50),
	}
	got, _ := NovelErrors(recent, nil, 10)
	if len(got) != 2 || got[0].Count != 50 {
		t.Fatalf("findings not ordered by count: %+v", got)
	}
}

func TestNovelErrorsIgnoresBlankDetail(t *testing.T) {
	// infra_error=1 with no detail carries nothing to group on; a bucket for it would
	// alert on "something failed, cause unknown" forever.
	got, dropped := NovelErrors([]DetailCount{detail("   ", 9)}, nil, 10)
	if len(got) != 0 || dropped != 0 {
		t.Errorf("blank detail produced findings %+v (dropped %d)", got, dropped)
	}
}

var thresholds = RateThresholds{MinSamples: 20, MinRate: 0.10, MinFactor: 2}

func TestInfraErrorStepChangeFiresOnRealJump(t *testing.T) {
	recent := Counts{Total: 100, InfraErrors: 40}    // 40%
	baseline := Counts{Total: 1000, InfraErrors: 50} // 5%
	got := InfraErrorStepChange(recent, baseline, thresholds)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Detector != DetectorInfraErrorRate {
		t.Errorf("detector = %q", got[0].Detector)
	}
	if !strings.Contains(got[0].Summary, "40") || !strings.Contains(got[0].Summary, "5") {
		t.Errorf("summary should carry both rates, got %q", got[0].Summary)
	}
}

func TestInfraErrorStepChangeIgnoresSmallSamples(t *testing.T) {
	// 2 of 3 pushes failing is 67% and means nothing. Without a floor, every quiet
	// hour with one bad push pages someone.
	got := InfraErrorStepChange(Counts{Total: 3, InfraErrors: 2}, Counts{Total: 1000, InfraErrors: 10}, thresholds)
	if len(got) != 0 {
		t.Errorf("fired on a 3-push window: %+v", got)
	}
}

func TestInfraErrorStepChangeNeedsBothAbsoluteAndRelative(t *testing.T) {
	cases := []struct {
		name             string
		recent, baseline Counts
	}{
		// 8% recent vs 1% baseline: 8x the baseline, but below the absolute floor —
		// a service that normally never fails will trip a pure ratio on noise.
		{"below absolute floor", Counts{Total: 100, InfraErrors: 8}, Counts{Total: 1000, InfraErrors: 10}},
		// 30% recent vs 25% baseline: over the floor, but this is the steady state,
		// not a change. A pure threshold would alert every single run forever.
		{"no step change", Counts{Total: 100, InfraErrors: 30}, Counts{Total: 1000, InfraErrors: 250}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := InfraErrorStepChange(c.recent, c.baseline, thresholds); len(got) != 0 {
				t.Errorf("fired: %+v", got)
			}
		})
	}
}

func TestInfraErrorStepChangeFiresWhenBaselineIsClean(t *testing.T) {
	// Zero baseline makes the ratio undefined; going from zero to 30% is the clearest
	// step change there is, so it must not be swallowed by a division guard.
	got := InfraErrorStepChange(Counts{Total: 100, InfraErrors: 30}, Counts{Total: 500, InfraErrors: 0}, thresholds)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func TestInfraErrorStepChangeSignatureIsStable(t *testing.T) {
	// The cooldown is keyed on (detector, signature). If the signature carried the
	// rate, every run would produce a new key and the cooldown would never suppress.
	a := InfraErrorStepChange(Counts{Total: 100, InfraErrors: 40}, Counts{Total: 1000, InfraErrors: 50}, thresholds)
	b := InfraErrorStepChange(Counts{Total: 100, InfraErrors: 55}, Counts{Total: 1000, InfraErrors: 50}, thresholds)
	if len(a) != 1 || len(b) != 1 {
		t.Fatal("expected both to fire")
	}
	if a[0].Signature != b[0].Signature {
		t.Errorf("signature varies with the rate: %q vs %q", a[0].Signature, b[0].Signature)
	}
}

func TestKilledScansCountsEveryKillSignature(t *testing.T) {
	recent := []DetailCount{
		detail("run grype: signal: killed", 4),
		detail("run grype: exit status 137", 2),
		detail("run grype: signal: SIGKILL", 1),
		detail("run grype: exit status 1: failed to catalog", 30), // not a kill
	}
	got := KilledScans(recent, 5)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].Detector != DetectorKilledScan {
		t.Errorf("detector = %q", got[0].Detector)
	}
	if got[0].Count != 7 {
		t.Errorf("count = %d, want 7 (4+2+1, excluding the exit-status-1 rows)", got[0].Count)
	}
}

func TestKilledScansRespectsThreshold(t *testing.T) {
	recent := []DetailCount{detail("run grype: signal: killed", 2)}
	if got := KilledScans(recent, 5); len(got) != 0 {
		t.Errorf("fired below threshold: %+v", got)
	}
	if got := KilledScans(recent, 2); len(got) != 1 {
		t.Errorf("did not fire at threshold: %+v", got)
	}
}

func TestKilledScansSignatureIsStable(t *testing.T) {
	// Same reason as the rate detector: a count in the signature defeats the cooldown.
	a := KilledScans([]DetailCount{detail("run grype: signal: killed", 9)}, 5)
	b := KilledScans([]DetailCount{detail("run grype: signal: killed", 40)}, 5)
	if a[0].Signature != b[0].Signature {
		t.Errorf("signature varies with the count: %q vs %q", a[0].Signature, b[0].Signature)
	}
}
