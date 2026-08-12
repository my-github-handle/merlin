package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/merlin-gate/merlin/internal/alert"
	"github.com/merlin-gate/merlin/internal/config"
)

// alertConfig translates the YAML block into the alerter's own Config.
//
// Empty durations are left at zero so alert.ConfigWithDefaults supplies them: the
// tuned values have exactly one home, and adding a second copy here is how the two
// drift apart. Parse errors are returned, never defaulted over — falling back on a
// typo would run a schedule nobody asked for and look like it worked.
func alertConfig(a config.AlertsConfig) (alert.Config, error) {
	parse := func(field, v string) (time.Duration, error) {
		if v == "" {
			return 0, nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("alerts.%s %q: %w", field, v, err)
		}
		return d, nil
	}
	var (
		c   alert.Config
		err error
	)
	if c.Interval, err = parse("interval", a.Interval); err != nil {
		return alert.Config{}, err
	}
	if c.RecentWindow, err = parse("recent_window", a.RecentWindow); err != nil {
		return alert.Config{}, err
	}
	if c.BaselineWindow, err = parse("baseline_window", a.BaselineWindow); err != nil {
		return alert.Config{}, err
	}
	if c.Cooldown, err = parse("cooldown", a.Cooldown); err != nil {
		return alert.Config{}, err
	}
	c.KilledScanThreshold = a.KilledScanThreshold
	c.MaxNovelPerRun = a.MaxNovelPerRun
	c = alert.ConfigWithDefaults(c)

	// Rejected, not warned: each run looks back RecentWindow from now, so a window
	// shorter than the tick leaves a blind gap in every interval, and findings that
	// land in the gap are never seen by any run. That is silent under-reporting from a
	// component whose entire purpose is to end silent under-reporting.
	if c.RecentWindow < c.Interval {
		return alert.Config{}, fmt.Errorf("alerts: recent_window (%s) must be >= interval (%s), or findings between runs fall in no window", c.RecentWindow, c.Interval)
	}
	if c.BaselineWindow <= c.RecentWindow {
		return alert.Config{}, fmt.Errorf("alerts: baseline_window (%s) must exceed recent_window (%s), or novelty has nothing to compare against", c.BaselineWindow, c.RecentWindow)
	}
	return c, nil
}

// alertEnvironment labels every message. One Slack channel usually serves several
// deployments, so a message that does not say which one is nearly useless.
func alertEnvironment(a config.AlertsConfig) string {
	if a.Environment != "" {
		return a.Environment
	}
	// The pod name is the next best identifier available without config, and it
	// carries the release name as its prefix.
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "merlin"
}

// startAlerter launches the background alerter and returns a closer.
//
// It returns (nil, nil) when alerts are not configured — the gate must start with or
// without an alerter, and a missing webhook is a deliberate "off", not an error.
// Conversely a webhook that IS configured but cannot connect is fatal: a deployment
// that believes it is being watched and is not is worse than one that knows it isn't.
func startAlerter(ctx context.Context, cfg config.Config) (func(), error) {
	if !cfg.Alerts.Enabled() {
		return nil, nil
	}
	acfg, err := alertConfig(cfg.Alerts)
	if err != nil {
		return nil, err
	}
	// Baseline novelty is judged against history that the audit TTL may already have
	// deleted. Logged rather than rejected: the alerter still works, it just judges
	// novelty against a shorter baseline than configured.
	if days := cfg.Audit.RetentionDays; days > 0 && acfg.BaselineWindow > time.Duration(days)*24*time.Hour {
		log.Printf("alerts: baseline_window %s exceeds audit retention of %dd; novelty will be judged against the retained history only",
			acfg.BaselineWindow, days)
	}
	store, err := alert.NewClickHouseStore(cfg.Audit.ClickHouseDSN)
	if err != nil {
		return nil, fmt.Errorf("create alert store: %w", err)
	}
	runner := &alert.Runner{
		Source:    store,
		Cooldowns: store,
		Notifier:  alert.NewSlack(cfg.Alerts.SlackWebhookURL, alertEnvironment(cfg.Alerts)),
		Config:    acfg,
	}
	go runner.Run(ctx)
	log.Printf("alerts: enabled (every %s, recent %s vs baseline %s, cooldown %s)",
		acfg.Interval, acfg.RecentWindow, acfg.BaselineWindow, acfg.Cooldown)
	return func() { store.Close() }, nil
}
