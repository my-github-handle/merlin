package alert

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fakes -----------------------------------------------------------------

type window struct{ since, until time.Time }

type fakeSource struct {
	mu       sync.Mutex
	details  map[window][]DetailCount
	counts   map[window]Counts
	windows  []window
	err      error
	fallback []DetailCount // returned for any window not in details
}

func (f *fakeSource) InfraErrorDetails(_ context.Context, since, until time.Time, _ int) ([]DetailCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	w := window{since, until}
	f.windows = append(f.windows, w)
	if d, ok := f.details[w]; ok {
		return d, nil
	}
	return f.fallback, nil
}

func (f *fakeSource) DecisionCounts(_ context.Context, since, until time.Time) (Counts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Counts{}, f.err
	}
	return f.counts[window{since, until}], nil
}

type fakeCooldowns struct {
	mu       sync.Mutex
	last     map[string]time.Time
	recorded []string
	loadErr  error
	saveErr  error
}

func newCooldowns() *fakeCooldowns {
	return &fakeCooldowns{last: map[string]time.Time{}}
}

func (f *fakeCooldowns) LastNotified(context.Context) (map[string]time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	out := make(map[string]time.Time, len(f.last))
	for k, v := range f.last {
		out[k] = v
	}
	return out, nil
}

func (f *fakeCooldowns) RecordNotified(_ context.Context, fi Finding, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.recorded = append(f.recorded, CooldownKey(fi))
	f.last[CooldownKey(fi)] = at
	return nil
}

type fakeNotifier struct {
	mu   sync.Mutex
	sent []Finding
	err  error
}

func (f *fakeNotifier) Notify(_ context.Context, fi Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, fi)
	return nil
}

func (f *fakeNotifier) signatures() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.sent))
	for _, s := range f.sent {
		out = append(out, s.Signature)
	}
	return out
}

// --- helpers ---------------------------------------------------------------

var runNow = time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

func newRunner(src Source, cd Cooldowns, n Notifier) *Runner {
	r := &Runner{
		Source:    src,
		Cooldowns: cd,
		Notifier:  n,
		Config: Config{
			Interval:            15 * time.Minute,
			RecentWindow:        time.Hour,
			BaselineWindow:      7 * 24 * time.Hour,
			Cooldown:            6 * time.Hour,
			Rate:                RateThresholds{MinSamples: 20, MinRate: 0.10, MinFactor: 2},
			KilledScanThreshold: 5,
			MaxNovelPerRun:      10,
			DetailLimit:         500,
		},
		now: func() time.Time { return runNow },
	}
	return r
}

// --- tests -----------------------------------------------------------------

func TestRunOnceBaselineWindowExcludesRecentWindow(t *testing.T) {
	// If the baseline overlaps the recent window, every novel signature is present in
	// its own baseline and the novelty detector can never fire. The windows must be
	// adjacent and half-open.
	src := &fakeSource{details: map[window][]DetailCount{}, counts: map[window]Counts{}}
	r := newRunner(src, newCooldowns(), &fakeNotifier{})
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(src.windows) != 2 {
		t.Fatalf("queried %d windows, want 2 (recent + baseline)", len(src.windows))
	}
	recent, baseline := src.windows[0], src.windows[1]
	if !recent.until.Equal(runNow) || !recent.since.Equal(runNow.Add(-time.Hour)) {
		t.Errorf("recent window = [%s, %s)", recent.since, recent.until)
	}
	if !baseline.until.Equal(recent.since) {
		t.Errorf("baseline ends at %s, want it to end where recent begins (%s)", baseline.until, recent.since)
	}
	if !baseline.since.Equal(recent.since.Add(-7 * 24 * time.Hour)) {
		t.Errorf("baseline window = [%s, %s)", baseline.since, baseline.until)
	}
}

func TestRunOnceNotifiesNovelFinding(t *testing.T) {
	recent := window{runNow.Add(-time.Hour), runNow}
	src := &fakeSource{
		details: map[window][]DetailCount{
			recent: {detail("staging: CROSSSLOT keys do not hash to the same slot", 2)},
		},
		counts: map[window]Counts{},
	}
	n := &fakeNotifier{}
	cd := newCooldowns()
	r := newRunner(src, cd, n)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := n.signatures(); len(got) != 1 || !strings.Contains(got[0], "CROSSSLOT") {
		t.Fatalf("notified %v, want one CROSSSLOT finding", got)
	}
	if len(cd.recorded) != 1 {
		t.Errorf("recorded %d cooldowns, want 1", len(cd.recorded))
	}
}

func TestRunOnceSuppressesWithinCooldown(t *testing.T) {
	recent := window{runNow.Add(-time.Hour), runNow}
	src := &fakeSource{
		details: map[window][]DetailCount{recent: {detail("brand new failure", 2)}},
		counts:  map[window]Counts{},
	}
	n := &fakeNotifier{}
	cd := newCooldowns()
	r := newRunner(src, cd, n)

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	// Second run, same tick: the failure is still firing, but it has already been said.
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if got := n.signatures(); len(got) != 1 {
		t.Fatalf("notified %d times, want 1: %v", len(got), got)
	}
}

func TestRunOnceSuppressionDoesNotExtendTheCooldown(t *testing.T) {
	// The cooldown must run from the last NOTIFICATION, not the last firing. If a
	// suppressed firing rewrote the timestamp, an ongoing failure would roll the
	// window forward on every tick and never be mentioned again.
	recent := window{runNow.Add(-time.Hour), runNow}
	src := &fakeSource{
		details: map[window][]DetailCount{recent: {detail("brand new failure", 2)}},
		counts:  map[window]Counts{},
	}
	n := &fakeNotifier{}
	cd := newCooldowns()
	r := newRunner(src, cd, n)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstRecord := len(cd.recorded)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cd.recorded) != firstRecord {
		t.Errorf("a suppressed finding was recorded again (%d -> %d)", firstRecord, len(cd.recorded))
	}
}

func TestRunOnceNotifiesAgainAfterCooldownExpires(t *testing.T) {
	recent := window{runNow.Add(-time.Hour), runNow}
	src := &fakeSource{
		details: map[window][]DetailCount{recent: {detail("brand new failure", 2)}},
		counts:  map[window]Counts{},
	}
	n := &fakeNotifier{}
	cd := newCooldowns()
	r := newRunner(src, cd, n)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Age the recorded notification past the cooldown.
	cd.mu.Lock()
	for k := range cd.last {
		cd.last[k] = runNow.Add(-7 * time.Hour)
	}
	cd.mu.Unlock()
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := n.signatures(); len(got) != 2 {
		t.Errorf("notified %d times, want 2 (cooldown had expired): %v", len(got), got)
	}
}

func TestRunOnceDoesNotRecordWhenDeliveryFails(t *testing.T) {
	// Recording a cooldown for a message that was never delivered swallows the
	// finding for a whole cooldown period — the failure mode is silence.
	recent := window{runNow.Add(-time.Hour), runNow}
	src := &fakeSource{
		details: map[window][]DetailCount{recent: {detail("brand new failure", 2)}},
		counts:  map[window]Counts{},
	}
	n := &fakeNotifier{err: errors.New("slack 500")}
	cd := newCooldowns()
	r := newRunner(src, cd, n)
	err := r.RunOnce(context.Background())
	if err == nil {
		t.Error("RunOnce should report a delivery failure")
	}
	if len(cd.recorded) != 0 {
		t.Errorf("recorded a cooldown for an undelivered finding: %v", cd.recorded)
	}
}

func TestRunOnceReportsSourceFailure(t *testing.T) {
	src := &fakeSource{err: errors.New("clickhouse down")}
	r := newRunner(src, newCooldowns(), &fakeNotifier{})
	if err := r.RunOnce(context.Background()); err == nil {
		t.Error("RunOnce should report a query failure rather than treat it as 'nothing wrong'")
	}
}

func TestRunOnceLogsWhatTheCapDropped(t *testing.T) {
	recent := window{runNow.Add(-time.Hour), runNow}
	var details []DetailCount
	for _, s := range []string{"a", "b", "c", "d"} {
		details = append(details, detail("brand new failure "+s, 1))
	}
	src := &fakeSource{details: map[window][]DetailCount{recent: details}, counts: map[window]Counts{}}
	r := newRunner(src, newCooldowns(), &fakeNotifier{})
	r.Config.MaxNovelPerRun = 2
	var logged []string
	r.Logf = func(f string, a ...any) { logged = append(logged, f) }
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, l := range logged {
		if strings.Contains(l, "not reported") {
			found = true
		}
	}
	if !found {
		t.Errorf("cap truncated the run without saying so; logged: %v", logged)
	}
}

func TestRunOnceRunsAllThreeDetectors(t *testing.T) {
	recentW := window{runNow.Add(-time.Hour), runNow}
	baselineW := window{recentW.since.Add(-7 * 24 * time.Hour), recentW.since}
	src := &fakeSource{
		details: map[window][]DetailCount{
			recentW: {
				detail("run grype: signal: killed", 9),              // killed_scan
				detail("staging: a completely new failure mode", 3), // novel_error
			},
			baselineW: {detail("run grype: signal: killed", 100)}, // makes the kill NOT novel
		},
		counts: map[window]Counts{
			recentW:   {Total: 100, InfraErrors: 40},
			baselineW: {Total: 1000, InfraErrors: 50},
		},
	}
	n := &fakeNotifier{}
	r := newRunner(src, newCooldowns(), n)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	n.mu.Lock()
	for _, f := range n.sent {
		got[f.Detector] = true
	}
	n.mu.Unlock()
	for _, d := range []string{DetectorNovelError, DetectorInfraErrorRate, DetectorKilledScan} {
		if !got[d] {
			t.Errorf("detector %s did not fire", d)
		}
	}
	if len(got) != 3 {
		t.Errorf("fired detectors = %v", got)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	src := &fakeSource{details: map[window][]DetailCount{}, counts: map[window]Counts{}}
	r := newRunner(src, newCooldowns(), &fakeNotifier{})
	r.Config.Interval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestRunSurvivesQueryFailures(t *testing.T) {
	// A ClickHouse blip must not silently end alerting for the lifetime of the pod.
	src := &fakeSource{err: errors.New("clickhouse down")}
	r := newRunner(src, newCooldowns(), &fakeNotifier{})
	r.Config.Interval = time.Millisecond
	var mu sync.Mutex
	var n int
	r.Logf = func(string, ...any) { mu.Lock(); n++; mu.Unlock() }
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if n < 2 {
		t.Errorf("logged %d failures; the loop stopped at the first error", n)
	}
}
