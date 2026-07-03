// Package imageage implements Merlin's image-age gate policy: it rejects an image
// whose config "created" timestamp is older than a per-tenant threshold.
package imageage

import "time"

const hoursPerDay = 24

// ageDays returns floor((now - created) / 24h), clamped to >= 0 (a future
// created timestamp, e.g. from clock skew or a zeroed reproducible build, is 0).
func ageDays(created, now time.Time) int {
	d := now.Sub(created)
	if d < 0 {
		return 0
	}
	return int(d.Hours() / hoursPerDay)
}
