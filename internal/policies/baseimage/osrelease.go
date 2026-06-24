// Package baseimage implements the base-image allow-list policy.
package baseimage

import (
	"strings"
)

// OSRelease holds parsed /etc/os-release contents.
type OSRelease struct {
	ID     string
	Fields map[string]string
}

// ParseOSRelease parses os-release KEY=value lines.
func ParseOSRelease(contents string) OSRelease {
	osr := OSRelease{Fields: make(map[string]string)}
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		osr.Fields[k] = v
		if k == "ID" {
			osr.ID = strings.ToLower(v)
		}
	}
	return osr
}
