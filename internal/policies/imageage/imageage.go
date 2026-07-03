package imageage

import (
	"context"
	"fmt"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Rule is the per-tenant age configuration: whether the policy is enabled and,
// if so, the maximum permitted age in days.
type Rule struct {
	Enabled       bool
	ThresholdDays int
}

// Policy is the image-age gate policy. It is stateless per call (each Evaluate
// carries its result back on the Verdict), so one Policy is safe for concurrent
// gates. now is injectable for deterministic tests; it defaults to time.Now.
type Policy struct {
	defaultRule Rule
	perTenant   map[string]Rule
	now         func() time.Time
}

// New builds an image-age policy. defaultRule applies to any tenant without an
// explicit entry in perTenant.
func New(defaultRule Rule, perTenant map[string]Rule) *Policy {
	return &Policy{defaultRule: defaultRule, perTenant: perTenant, now: time.Now}
}

func (p *Policy) Name() string { return "imageage" }

// ruleFor returns the age rule governing the given tenant prefix.
func (p *Policy) ruleFor(prefix string) Rule {
	if r, ok := p.perTenant[prefix]; ok {
		return r
	}
	return p.defaultRule
}

func (p *Policy) Evaluate(_ context.Context, img policy.StagedImage) (policy.Verdict, error) {
	rule := p.ruleFor(img.Prefix)
	if !rule.Enabled {
		// Policy disabled for this tenant: do not gate, do not report age.
		return policy.Verdict{Passed: true}, nil
	}

	// Fail closed: an image whose created timestamp could not be determined is
	// rejected with a reason clearly distinct from a "too old" verdict (spec §3.5).
	if img.Created.IsZero() {
		return policy.Verdict{
			Passed:  false,
			Reasons: []string{"could not determine image age (image config is missing a readable created timestamp)"},
			Age:     &policy.AgeInfo{Known: false, ThresholdDays: rule.ThresholdDays, Compliant: false},
		}, nil
	}

	age := ageDays(img.Created, p.now().UTC())
	compliant := age <= rule.ThresholdDays
	info := &policy.AgeInfo{
		Known:         true,
		Created:       img.Created,
		AgeDays:       age,
		ThresholdDays: rule.ThresholdDays,
		Compliant:     compliant,
	}
	if compliant {
		return policy.Verdict{Passed: true, Age: info}, nil
	}
	return policy.Verdict{
		Passed: false,
		Reasons: []string{fmt.Sprintf(
			"image age %dd exceeds max %dd (created %s)",
			age, rule.ThresholdDays, img.Created.Format(time.RFC3339))},
		Age: info,
	}, nil
}
