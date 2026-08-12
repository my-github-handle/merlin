package alert

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Source reads the audit window. Two queries, both over gate_decisions.
type Source interface {
	// InfraErrorDetails groups the window's infra-error decisions by error_detail.
	// limit bounds how many distinct details come back.
	InfraErrorDetails(ctx context.Context, since, until time.Time, limit int) ([]DetailCount, error)
	// DecisionCounts returns the window's total decisions and how many were infra
	// errors.
	DecisionCounts(ctx context.Context, since, until time.Time) (Counts, error)
}

// Cooldowns remembers when each (detector, signature) was last ANNOUNCED. This is
// the whole of the deduplication design: no incident records, no lifecycle states,
// one timestamp per finding class.
type Cooldowns interface {
	LastNotified(ctx context.Context) (map[string]time.Time, error)
	RecordNotified(ctx context.Context, f Finding, at time.Time) error
}

// Notifier delivers one finding to a human.
type Notifier interface {
	Notify(ctx context.Context, f Finding) error
}

// CooldownKey identifies a finding class across runs.
func CooldownKey(f Finding) string { return f.Detector + "|" + f.Signature }

// Config tunes the run. Defaults are applied by ConfigWithDefaults.
type Config struct {
	Interval       time.Duration
	RecentWindow   time.Duration
	BaselineWindow time.Duration
	// Cooldown is how long a finding class stays quiet after being announced. It runs
	// from the last NOTIFICATION, not the last firing: a still-firing failure must
	// resurface when the cooldown expires, so a suppressed firing never rewrites the
	// timestamp.
	Cooldown            time.Duration
	Rate                RateThresholds
	KilledScanThreshold uint64
	// MaxNovelPerRun bounds how many novel signatures one run may announce. A bad
	// deploy can invent dozens at once, and a channel that receives dozens of messages
	// is a channel people mute. The remainder is logged, never dropped silently.
	MaxNovelPerRun int
	// DetailLimit bounds the distinct error_detail values fetched per window. Details
	// carry per-push text, so an unbounded GROUP BY is unbounded in the pod's memory.
	DetailLimit int
}

// Default tuning. The windows are deliberately asymmetric: "new in the last hour,
// compared against the last week" is the question the novelty detector answers, and
// a baseline shorter than a few days would call a Monday-morning failure novel every
// Monday.
const (
	DefaultInterval            = 15 * time.Minute
	DefaultRecentWindow        = time.Hour
	DefaultBaselineWindow      = 7 * 24 * time.Hour
	DefaultCooldown            = 6 * time.Hour
	DefaultKilledScanThreshold = 5
	DefaultMaxNovelPerRun      = 5
	DefaultDetailLimit         = 500
)

// ConfigWithDefaults fills unset fields. Zero thresholds are NOT treated as "alert
// on everything": a missing MinSamples/MinRate would turn the rate detector into a
// pager for any single failed push.
func ConfigWithDefaults(c Config) Config {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.RecentWindow <= 0 {
		c.RecentWindow = DefaultRecentWindow
	}
	if c.BaselineWindow <= 0 {
		c.BaselineWindow = DefaultBaselineWindow
	}
	if c.Cooldown <= 0 {
		c.Cooldown = DefaultCooldown
	}
	if c.Rate.MinSamples == 0 {
		c.Rate.MinSamples = 20
	}
	if c.Rate.MinRate <= 0 {
		c.Rate.MinRate = 0.10
	}
	if c.Rate.MinFactor <= 0 {
		c.Rate.MinFactor = 2
	}
	if c.KilledScanThreshold == 0 {
		c.KilledScanThreshold = DefaultKilledScanThreshold
	}
	if c.MaxNovelPerRun <= 0 {
		c.MaxNovelPerRun = DefaultMaxNovelPerRun
	}
	if c.DetailLimit <= 0 {
		c.DetailLimit = DefaultDetailLimit
	}
	return c
}

// Runner evaluates the detectors on a schedule and notifies what is new.
type Runner struct {
	Source    Source
	Cooldowns Cooldowns
	Notifier  Notifier
	Config    Config
	// Logf defaults to log.Printf. Every suppression, cap and failure goes through it:
	// the run must be explainable from the pod log alone, because the alternative is
	// wondering whether silence means healthy or broken.
	Logf func(format string, args ...any)

	now func() time.Time // tests
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (r *Runner) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Run evaluates on Config.Interval until ctx is done.
//
// A failed evaluation is logged and the loop continues: a ClickHouse restart must
// not end alerting for the lifetime of the pod, which is the failure mode where
// nobody notices anything is wrong ever again.
func (r *Runner) Run(ctx context.Context) {
	cfg := ConfigWithDefaults(r.Config)
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.RunOnce(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				r.logf("alert: evaluation failed: %v", err)
			}
		}
	}
}

// RunOnce evaluates every detector once and notifies the findings whose cooldown has
// expired.
func (r *Runner) RunOnce(ctx context.Context) error {
	cfg := ConfigWithDefaults(r.Config)
	now := r.clock()

	// Adjacent half-open windows. The baseline MUST end where the recent window
	// begins: if they overlap, every novel signature appears in its own baseline and
	// the novelty detector can never fire.
	recentSince := now.Add(-cfg.RecentWindow)
	baselineSince := recentSince.Add(-cfg.BaselineWindow)

	recentDetails, err := r.Source.InfraErrorDetails(ctx, recentSince, now, cfg.DetailLimit)
	if err != nil {
		return fmt.Errorf("query recent error details: %w", err)
	}
	baselineDetails, err := r.Source.InfraErrorDetails(ctx, baselineSince, recentSince, cfg.DetailLimit)
	if err != nil {
		return fmt.Errorf("query baseline error details: %w", err)
	}
	recentCounts, err := r.Source.DecisionCounts(ctx, recentSince, now)
	if err != nil {
		return fmt.Errorf("query recent decision counts: %w", err)
	}
	baselineCounts, err := r.Source.DecisionCounts(ctx, baselineSince, recentSince)
	if err != nil {
		return fmt.Errorf("query baseline decision counts: %w", err)
	}

	novel, dropped := NovelErrors(recentDetails, baselineDetails, cfg.MaxNovelPerRun)
	if dropped > 0 {
		r.logf("alert: %d further novel error signature(s) not reported this run (cap %d); query gate_decisions WHERE infra_error AND ts >= '%s' to see them all",
			dropped, cfg.MaxNovelPerRun, recentSince.UTC().Format(time.RFC3339))
	}
	findings := novel
	findings = append(findings, InfraErrorStepChange(recentCounts, baselineCounts, cfg.Rate)...)
	findings = append(findings, KilledScans(recentDetails, cfg.KilledScanThreshold)...)
	if len(findings) == 0 {
		return nil
	}

	last, err := r.Cooldowns.LastNotified(ctx)
	if err != nil {
		return fmt.Errorf("load cooldowns: %w", err)
	}

	var errs []error
	for _, f := range findings {
		key := CooldownKey(f)
		if at, ok := last[key]; ok && now.Sub(at) < cfg.Cooldown {
			// Deliberately NOT recorded: recording here would roll the cooldown forward
			// on every tick and the finding would never resurface.
			r.logf("alert: %s suppressed, last notified %s ago (cooldown %s)",
				key, now.Sub(at).Truncate(time.Second), cfg.Cooldown)
			continue
		}
		if err := r.Notifier.Notify(ctx, f); err != nil {
			errs = append(errs, fmt.Errorf("notify %s: %w", key, err))
			// No cooldown recorded: an undelivered finding must be retried, not
			// silenced for a whole cooldown period.
			continue
		}
		if err := r.Cooldowns.RecordNotified(ctx, f, now); err != nil {
			// The message went out. Failing to record it means it may be repeated next
			// tick — noisy, but the safe direction.
			errs = append(errs, fmt.Errorf("record cooldown %s: %w", key, err))
		}
	}
	return errors.Join(errs...)
}
