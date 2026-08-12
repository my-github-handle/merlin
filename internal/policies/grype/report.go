// Package grype implements the Grype vulnerability-scan policy.
package grype

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Report is the parsed result of a Grype scan.
type Report struct {
	DBVersion string
	// DBBuilt is when the vulnerability DB was built, zero when grype did not
	// report a parseable timestamp. It is kept SEPARATELY from DBVersion — which
	// stays the human-readable audit value — because the DB's age has to be
	// arithmetic to be a metric, and re-parsing it back out of a formatted string
	// would break the moment that format changed.
	DBBuilt  time.Time
	Findings []policy.Finding
}

// parseDBBuilt reads grype's descriptor.db.status.built timestamp, returning the
// zero time when it is absent or in an unrecognized format.
//
// It must NOT be an error: the scan itself succeeded, and this gate is
// fail-closed, so turning an unfamiliar timestamp into a scan failure would turn a
// cosmetic upstream format change into a rejected push. An unknown age is reported
// as unknown instead (see Policy.observeDBAge).
func parseDBBuilt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// RFC3339 also accepts the fractional-second form grype emits.
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

type grypeJSON struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Fix      struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
	Descriptor struct {
		DB struct {
			Status struct {
				SchemaVersion string `json:"schemaVersion"`
				Built         string `json:"built"`
			} `json:"status"`
		} `json:"db"`
	} `json:"descriptor"`
}

// ParseReport parses Grype `-o json` output into a Report. It requires a
// descriptor.db object (grype always emits one) so a non-grype JSON payload is
// rejected rather than silently yielding an empty report.
func ParseReport(raw []byte) (Report, error) {
	// Distinguish "valid grype report, no matches" from "not a grype report".
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Report{}, fmt.Errorf("parse grype json: %w", err)
	}
	if _, ok := probe["descriptor"]; !ok {
		return Report{}, fmt.Errorf("parse grype json: missing descriptor (not a valid grype report)")
	}
	var gj grypeJSON
	if err := json.Unmarshal(raw, &gj); err != nil {
		return Report{}, fmt.Errorf("parse grype json: %w", err)
	}
	rep := Report{
		DBVersion: fmt.Sprintf("schema %s built %s", gj.Descriptor.DB.Status.SchemaVersion, gj.Descriptor.DB.Status.Built),
		DBBuilt:   parseDBBuilt(gj.Descriptor.DB.Status.Built),
	}
	for _, m := range gj.Matches {
		var fixed string
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixed = m.Vulnerability.Fix.Versions[0]
		}
		// Normalize to UPPER-CASE so stored severities match the ClickHouse
		// severity enum labels (UNKNOWN/NEGLIGIBLE/LOW/MEDIUM/HIGH/CRITICAL) and
		// the ranking map keys. Grype emits title-case ("Critical", "Negligible").
		sev := strings.ToUpper(strings.TrimSpace(m.Vulnerability.Severity))
		if sev == "" {
			sev = "UNKNOWN"
		}
		rep.Findings = append(rep.Findings, policy.Finding{
			CVE:          m.Vulnerability.ID,
			Severity:     sev,
			Pkg:          m.Artifact.Name,
			Version:      m.Artifact.Version,
			FixedVersion: fixed,
		})
	}
	return rep, nil
}
