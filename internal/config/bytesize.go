package config

import (
	"fmt"
	"strconv"
	"strings"
)

// binarySuffixes are the Kubernetes binary byte suffixes. Only binary units are
// accepted: these values are budgeted against a pod's resources.limits.memory,
// and mixing 2G with 2Gi in the same arithmetic silently loses 7%.
var binarySuffixes = []struct {
	suffix string
	mult   int64
}{
	{"ki", 1 << 10},
	{"mi", 1 << 20},
	{"gi", 1 << 30},
	{"ti", 1 << 40},
}

// ParseByteSize parses a byte count written either plainly ("1024") or with a
// Kubernetes binary suffix ("512Ki", "2Gi"). An empty string is 0, meaning
// "unset". Negative values and decimal SI suffixes are rejected.
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	lower := strings.ToLower(s)
	for _, u := range binarySuffixes {
		if !strings.HasSuffix(lower, u.suffix) {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(lower[:len(lower)-len(u.suffix)]), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse byte size %q: %w", s, err)
		}
		if n < 0 {
			return 0, fmt.Errorf("parse byte size %q: must not be negative", s)
		}
		if n > (1<<62)/u.mult {
			return 0, fmt.Errorf("parse byte size %q: overflows int64", s)
		}
		return n * u.mult, nil
	}
	n, err := strconv.ParseInt(lower, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse byte size %q: want a byte count or a binary suffix (Ki, Mi, Gi, Ti)", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("parse byte size %q: must not be negative", s)
	}
	return n, nil
}

// MemoryLimitBytes returns the configured per-scan memory bound in bytes, or 0
// when unset (unbounded). See GrypeConfig.MemoryLimit for the sizing rules.
func (g GrypeConfig) MemoryLimitBytes() (int64, error) {
	n, err := ParseByteSize(g.MemoryLimit)
	if err != nil {
		return 0, fmt.Errorf("grype.memory_limit: %w", err)
	}
	return n, nil
}
