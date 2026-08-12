package app

import (
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/alert"
	"github.com/merlin-gate/merlin/internal/config"
)

func TestAlertConfigUsesPackageDefaultsWhenUnset(t *testing.T) {
	// The tuned defaults live in internal/alert and must not be duplicated in the
	// translation: an operator who sets only the webhook gets the tuned windows.
	got, err := alertConfig(config.AlertsConfig{SlackWebhookURL: "https://hooks/x"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Interval != alert.DefaultInterval || got.RecentWindow != alert.DefaultRecentWindow ||
		got.BaselineWindow != alert.DefaultBaselineWindow || got.Cooldown != alert.DefaultCooldown {
		t.Errorf("defaults not applied: %+v", got)
	}
	if got.KilledScanThreshold != alert.DefaultKilledScanThreshold {
		t.Errorf("killed scan threshold = %d, want %d", got.KilledScanThreshold, alert.DefaultKilledScanThreshold)
	}
}

func TestAlertConfigTranslatesExplicitValues(t *testing.T) {
	got, err := alertConfig(config.AlertsConfig{
		SlackWebhookURL:     "https://hooks/x",
		Interval:            "5m",
		RecentWindow:        "30m",
		BaselineWindow:      "72h",
		Cooldown:            "2h",
		KilledScanThreshold: 2,
		MaxNovelPerRun:      3,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		got, want time.Duration
	}{
		{"interval", got.Interval, 5 * time.Minute},
		{"recent", got.RecentWindow, 30 * time.Minute},
		{"baseline", got.BaselineWindow, 72 * time.Hour},
		{"cooldown", got.Cooldown, 2 * time.Hour},
	} {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
	if got.KilledScanThreshold != 2 || got.MaxNovelPerRun != 3 {
		t.Errorf("thresholds not carried: %+v", got)
	}
}

func TestAlertConfigRejectsBadDuration(t *testing.T) {
	// Config.validate already rejects these, but the translation must not fall back to
	// a default on a parse error: that would silently run a schedule nobody asked for.
	if _, err := alertConfig(config.AlertsConfig{
		SlackWebhookURL: "https://hooks/x",
		Interval:        "fifteen minutes",
	}); err == nil {
		t.Fatal("accepted an unparseable interval")
	}
}

func TestAlertConfigWarnsWhenRecentWindowIsShorterThanInterval(t *testing.T) {
	// A 15m tick with a 5m window leaves 10m of every interval in no window at all.
	// That is a real misconfiguration, so it is rejected rather than logged.
	if _, err := alertConfig(config.AlertsConfig{
		SlackWebhookURL: "https://hooks/x",
		Interval:        "15m",
		RecentWindow:    "5m",
	}); err == nil {
		t.Fatal("accepted a recent_window shorter than the interval, which loses findings")
	}
}
