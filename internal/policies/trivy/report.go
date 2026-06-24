// Package trivy implements the Trivy vulnerability-scan policy.
package trivy

import (
	"encoding/json"
	"fmt"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Report is the parsed result of a Trivy scan.
type Report struct {
	DBVersion string
	Findings  []policy.Finding
}

type trivyJSON struct {
	Metadata struct {
		DBVersion string `json:"DBVersion"`
	} `json:"Metadata"`
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			Severity         string `json:"Severity"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseReport parses Trivy `--format json` output into a Report.
func ParseReport(raw []byte) (Report, error) {
	var tj trivyJSON
	if err := json.Unmarshal(raw, &tj); err != nil {
		return Report{}, fmt.Errorf("parse trivy json: %w", err)
	}
	rep := Report{DBVersion: tj.Metadata.DBVersion}
	for _, res := range tj.Results {
		for _, v := range res.Vulnerabilities {
			rep.Findings = append(rep.Findings, policy.Finding{
				CVE:          v.VulnerabilityID,
				Severity:     v.Severity,
				Pkg:          v.PkgName,
				Version:      v.InstalledVersion,
				FixedVersion: v.FixedVersion,
			})
		}
	}
	return rep, nil
}
