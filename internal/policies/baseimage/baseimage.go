package baseimage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Policy enforces that the image's base OS ID is in the allow-list.
type Policy struct {
	allowed map[string]bool
	list    []string
}

// New builds a base-image policy from the allowed OS IDs.
func New(allowedIDs []string) *Policy {
	m := make(map[string]bool, len(allowedIDs))
	for _, id := range allowedIDs {
		m[strings.ToLower(id)] = true
	}
	return &Policy{allowed: m, list: allowedIDs}
}

func (p *Policy) Name() string { return "baseimage" }

func (p *Policy) Evaluate(_ context.Context, img policy.StagedImage) (policy.Verdict, error) {
	// Per the os-release spec, the file lives at /etc/os-release with a fallback to
	// /usr/lib/os-release. In UBI/Chainguard images /etc/os-release is a symlink to
	// ../usr/lib/os-release; Merlin skips symlinks during layer extraction (escape-
	// surface reduction), so for those images only the /usr/lib copy is present in
	// the assembled rootfs. Check both locations.
	var raw []byte
	var err error
	for _, rel := range []string{
		filepath.Join("etc", "os-release"),
		filepath.Join("usr", "lib", "os-release"),
	} {
		raw, err = os.ReadFile(filepath.Join(img.FSPath, rel))
		if err == nil {
			break
		}
	}
	if err != nil {
		return policy.Verdict{
			Passed:  false,
			Reasons: []string{"base image not permitted: os-release not found (checked /etc/os-release and /usr/lib/os-release)"},
		}, nil
	}
	osr := ParseOSRelease(string(raw))
	if osr.ID == "" || !p.allowed[osr.ID] {
		return policy.Verdict{
			Passed: false,
			Reasons: []string{fmt.Sprintf(
				"base image not permitted: detected %q, allowed: %s",
				osr.ID, strings.Join(p.list, ", "))},
		}, nil
	}
	return policy.Verdict{Passed: true}, nil
}
