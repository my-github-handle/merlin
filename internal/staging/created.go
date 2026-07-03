package staging

import (
	"encoding/json"
	"fmt"
	"time"
)

// parseImageCreated extracts the "created" timestamp from an OCI/Docker image
// config blob. The field is RFC3339 (optionally with sub-second precision); this
// mirrors what `docker inspect -f '{{.Created}}'` returns. A missing, empty, or
// unparseable value is an error — the caller decides how to treat unknown age
// (the image-age policy fails closed).
func parseImageCreated(configRaw []byte) (time.Time, error) {
	var cfg struct {
		Created string `json:"created"`
	}
	if err := json.Unmarshal(configRaw, &cfg); err != nil {
		return time.Time{}, fmt.Errorf("parse image config: %w", err)
	}
	if cfg.Created == "" {
		return time.Time{}, fmt.Errorf("image config has no created timestamp")
	}
	if t, err := time.Parse(time.RFC3339, cfg.Created); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, cfg.Created)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse created %q: %w", cfg.Created, err)
	}
	return t.UTC(), nil
}
