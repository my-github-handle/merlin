package imageage

import (
	"testing"
	"time"
)

func TestAgeDays(t *testing.T) {
	now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		created time.Time
		want    int
	}{
		{"same instant", now, 0},
		{"one day ago", now.Add(-24 * time.Hour), 1},
		{"sixty days ago", now.Add(-60 * 24 * time.Hour), 60},
		{"partial day floors down", now.Add(-47 * time.Hour), 1},
		{"future clamps to zero", now.Add(48 * time.Hour), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ageDays(tt.created, now); got != tt.want {
				t.Fatalf("ageDays = %d, want %d", got, tt.want)
			}
		})
	}
}
