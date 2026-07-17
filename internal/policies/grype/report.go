// Package grype implements the Grype vulnerability-scan policy.
package grype

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Report is the parsed result of a Grype scan.
type Report struct {
	DBVersion string
	Findings  []policy.Finding
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
			SchemaVersion int    `json:"schemaVersion"`
			Built         string `json:"built"`
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
	rep := Report{DBVersion: fmt.Sprintf("schema %d built %s", gj.Descriptor.DB.SchemaVersion, gj.Descriptor.DB.Built)}
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
