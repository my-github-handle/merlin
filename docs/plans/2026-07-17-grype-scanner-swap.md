# Replace Trivy with Grype — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Trivy with Grype as Merlin's vulnerability scanner (hard swap; Trivy removed entirely).

**Architecture:** Grype is isolated behind the same `Runner`/`ParseReport`/`Policy` shape Trivy used. The package `internal/policies/trivy` is renamed to `internal/policies/grype`, the exec command and JSON parser change to Grype's, the Dockerfile ships the grype binary (runtime DB, same as trivy), config `Trivy`→`Grype`, and the audit column `trivy_db_version` is renamed to the scanner-agnostic `scanner_db_version` via an expand/contract migration.

**Tech Stack:** Go 1.26, ClickHouse (audit store), Grype (anchore) native JSON, Docker/buildx, Helm.

## Global Constraints

- Scanner: **Grype**, invoked as `grype <ociPath> -o json -q` against the assembled OCI layout dir.
- Grype severities: `Negligible, Low, Medium, High, Critical, Unknown`. Ranking: `Unknown=0 < Negligible=1 < Low=2 < Medium=3 < High=4 < Critical=5`.
- Config default severity threshold stays `CRITICAL`.
- DB-version field renamed scanner-agnostic: Go `ScannerDBVersion`, column `scanner_db_version`.
- Policy `Name()` returns `"grype"`.
- Pin the grype image to an explicit tag (NOT `latest`): use `anchore/grype:v0.98.0` (adjust only if that tag is unavailable at build time; never `latest`).
- Migration is **expand/contract**: add new column → deploy → drop old column. Never a bare `RENAME` against the live DB.
- All existing tests must stay green: `go build ./...`, `go test -race ./...`, `go vet -tags integration ./...`.
- ClickHouse context for live migration steps: `kubectl --context azplatdevops-kube-01 -n c3-opsadmin exec chi-merlin-ch-merlin-0-0-0 -c clickhouse -- clickhouse-client -q "<SQL>"`.

---

## File Structure

- `internal/policies/grype/exec_runner.go` (created; from trivy/exec_runner.go) — `Runner` iface + grype exec.
- `internal/policies/grype/report.go` (created; from trivy/report.go) — grype JSON parser.
- `internal/policies/grype/grype.go` (created; from trivy/trivy.go) — `Policy`.
- `internal/policies/grype/*_test.go` (created) — ported tests + grype fixture.
- `internal/policies/trivy/` (deleted).
- `internal/policy/policy.go` (modify) — `Result.TrivyDBVersion` → `ScannerDBVersion`.
- `internal/policy/engine.go` (modify) — identity assignment.
- `internal/audit/audit.go`, `clickhouse.go`, `dashboard_reader.go`, `dashboard_queries.go`, `schema.sql` (modify) — field + column rename, enum.
- `internal/dashboard/view.go`, `data.go`, `templates/report.html` (modify) — field + label.
- `internal/observability/metrics.go` (modify) — metric rename.
- `internal/config/config.go` (modify) — `Trivy`→`Grype` config.
- `internal/app/app.go` (modify) — wiring.
- `Dockerfile` (modify) — grype stage.
- `charts/merlin/templates/configmap.yaml`, `charts/merlin/values.yaml` (modify) — config key.
- Numerous `*_test.go` across app/ingress/dashboard/audit (modify) — rename fallout.

---

## Task 1: Grype JSON parser (`report.go`)

**Files:**
- Create: `internal/policies/grype/report.go`
- Create: `internal/policies/grype/report_test.go`
- Create: `internal/policies/grype/testdata/grype-sample.json`

**Interfaces:**
- Consumes: `policy.Finding{CVE, Severity, Pkg, Version, FixedVersion string}` (existing).
- Produces: `type Report struct { DBVersion string; Findings []policy.Finding }`; `func ParseReport(raw []byte) (Report, error)`.

- [ ] **Step 1: Capture a real grype fixture**

Run grype against a known-vulnerable image and save the JSON. If grype/docker is available locally:

```bash
mkdir -p internal/policies/grype/testdata
grype anchore/test_images:vulnerabilities-alpine-3.7 -o json -q > internal/policies/grype/testdata/grype-sample.json 2>/dev/null || true
```

If that is not runnable in the worker environment, hand-author the fixture from Grype's documented schema. It MUST contain: a `descriptor.db` object with `schemaVersion` and `built`; a `matches` array with at least one `Negligible` finding and one finding whose `vulnerability.fix.versions` has an entry. Minimal valid fixture:

```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2024-0001", "severity": "Critical",
        "fix": { "versions": ["1.1.1w-r0"], "state": "fixed" }
      },
      "artifact": { "name": "openssl", "version": "1.1.1k-r0" }
    },
    {
      "vulnerability": {
        "id": "CVE-2024-0002", "severity": "Negligible",
        "fix": { "versions": [], "state": "not-fixed" }
      },
      "artifact": { "name": "busybox", "version": "1.30.1-r5" }
    }
  ],
  "descriptor": { "db": { "schemaVersion": 5, "built": "2026-07-16T01:02:03Z" } }
}
```

- [ ] **Step 2: Write the failing test**

```go
package grype

import (
	"os"
	"testing"
)

func TestParseReportGrypeJSON(t *testing.T) {
	raw, err := os.ReadFile("testdata/grype-sample.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	rep, err := ParseReport(raw)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if rep.DBVersion == "" {
		t.Error("DBVersion should be populated from descriptor.db")
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(rep.Findings))
	}
	f0 := rep.Findings[0]
	// Parser normalizes severity to UPPER-CASE (matches CH enum + ranking keys).
	if f0.CVE != "CVE-2024-0001" || f0.Severity != "CRITICAL" ||
		f0.Pkg != "openssl" || f0.Version != "1.1.1k-r0" || f0.FixedVersion != "1.1.1w-r0" {
		t.Errorf("finding0 mismatch: %+v", f0)
	}
	f1 := rep.Findings[1]
	if f1.Severity != "NEGLIGIBLE" || f1.FixedVersion != "" {
		t.Errorf("finding1 (negligible, no fix) mismatch: %+v", f1)
	}
}

func TestParseReportRejectsNonGrypeJSON(t *testing.T) {
	if _, err := ParseReport([]byte(`{"foo":1}`)); err == nil {
		t.Error("expected error for JSON lacking matches/descriptor")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/policies/grype/ -run TestParseReport -v`
Expected: FAIL — `undefined: ParseReport` (package/functions don't exist yet).

- [ ] **Step 4: Write the parser**

```go
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/policies/grype/ -run TestParseReport -v`
Expected: PASS (both tests).

- [ ] **Step 6: Commit**

```bash
git add internal/policies/grype/report.go internal/policies/grype/report_test.go internal/policies/grype/testdata/grype-sample.json
git commit -m "feat(grype): parse grype native JSON into Report"
```

---

## Task 2: Grype policy (`grype.go`)

**Files:**
- Create: `internal/policies/grype/grype.go`
- Create: `internal/policies/grype/grype_test.go`

**Interfaces:**
- Consumes: `Report`, `ParseReport` (Task 1); `policy.StagedImage{OCIPath string}`, `policy.Verdict{Passed bool; Reasons []string; Findings []policy.Finding; ScannerDBVersion string}` (existing).
- Produces: `type Runner interface { Scan(ctx context.Context, ociPath string) (Report, error) }`; `type Policy struct{...}`; `func New(runner Runner, threshold string) *Policy`; methods `Name() string`, `Evaluate(ctx, policy.StagedImage) (policy.Verdict, error)`.

- [ ] **Step 1: Write the failing test**

```go
package grype

import (
	"context"
	"errors"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

type fakeRunner struct {
	report Report
	err    error
}

func (f fakeRunner) Scan(_ context.Context, _ string) (Report, error) { return f.report, f.err }

func TestNameIsGrype(t *testing.T) {
	if New(fakeRunner{}, "CRITICAL").Name() != "grype" {
		t.Error("Name() should be grype")
	}
}

func TestEvaluateFailsOnCritical(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-1", Severity: "Critical", Pkg: "openssl", Version: "1.1.1"},
	}}}
	v, err := New(r, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Passed || len(v.Reasons) != 1 {
		t.Errorf("expected fail with 1 reason, got passed=%v reasons=%v", v.Passed, v.Reasons)
	}
}

func TestEvaluatePassesWhenBelowThreshold(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-2", Severity: "High", Pkg: "zlib", Version: "1.2.0"},
		{CVE: "CVE-3", Severity: "Negligible", Pkg: "p", Version: "1"},
	}}}
	v, err := New(r, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Passed {
		t.Errorf("expected pass when only High/Negligible present, reasons=%v", v.Reasons)
	}
}

func TestEvaluateNegligibleThreshold(t *testing.T) {
	// Threshold NEGLIGIBLE: even a Negligible finding fails.
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-4", Severity: "Negligible", Pkg: "p", Version: "1"},
	}}}
	v, _ := New(r, "NEGLIGIBLE").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if v.Passed {
		t.Error("Negligible finding must fail when threshold is NEGLIGIBLE")
	}
}

func TestEvaluateFailsClosedOnUnrecognizedSeverity(t *testing.T) {
	r := fakeRunner{report: Report{Findings: []policy.Finding{
		{CVE: "CVE-X", Severity: "WEIRD", Pkg: "p", Version: "1"},
	}}}
	v, _ := New(r, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if v.Passed {
		t.Error("unrecognized severity must fail closed")
	}
}

func TestEvaluateRunnerErrorIsInfraFailure(t *testing.T) {
	boom := errors.New("grype exited 2")
	_, err := New(fakeRunner{err: boom}, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if !errors.Is(err, boom) {
		t.Errorf("expected wrapped runner error, got %v", err)
	}
}

func TestEvaluateEmptyOCIPathIsError(t *testing.T) {
	_, err := New(fakeRunner{}, "CRITICAL").Evaluate(context.Background(), policy.StagedImage{OCIPath: ""})
	if err == nil {
		t.Error("empty OCIPath must return an error")
	}
}

func TestVerdictCarriesFindings(t *testing.T) {
	findings := []policy.Finding{
		{CVE: "CVE-2024-1111", Severity: "Critical", Pkg: "curl", Version: "8.0.0"},
		{CVE: "CVE-2024-2222", Severity: "High", Pkg: "nginx", Version: "1.24.0"},
	}
	r := fakeRunner{report: Report{Findings: findings, DBVersion: "schema 5 built 2026-07-16"}}
	v, err := New(r, "HIGH").Evaluate(context.Background(), policy.StagedImage{OCIPath: "/oci"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(v.Findings) != 2 || v.Findings[0].CVE != "CVE-2024-1111" {
		t.Errorf("verdict findings mismatch: %+v", v.Findings)
	}
	if v.ScannerDBVersion != "schema 5 built 2026-07-16" {
		t.Errorf("ScannerDBVersion = %q", v.ScannerDBVersion)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policies/grype/ -run TestEvaluate -v`
Expected: FAIL — `undefined: New` / `undefined: Runner`.

- [ ] **Step 3: Write the policy**

```go
package grype

import (
	"context"
	"fmt"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Runner runs a Grype scan against an on-disk OCI layout.
type Runner interface {
	Scan(ctx context.Context, ociPath string) (Report, error)
}

// Policy is the Grype vulnerability-scan policy. Stateless across calls: each
// Evaluate carries its findings back through the returned Verdict, so the same
// Policy is safe to use from concurrent gates.
type Policy struct {
	runner    Runner
	threshold string
}

// severityRank orders Grype severities so we can compare against a threshold.
// Grype casing is title-case (e.g. "Critical"); the threshold arrives upper-case
// from config, so both are upper-cased before lookup.
var severityRank = map[string]int{
	"UNKNOWN": 0, "NEGLIGIBLE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5,
}

// New builds a Grype policy that fails on findings at/above threshold.
func New(runner Runner, threshold string) *Policy {
	return &Policy{runner: runner, threshold: threshold}
}

func (p *Policy) Name() string { return "grype" }

func (p *Policy) Evaluate(ctx context.Context, img policy.StagedImage) (policy.Verdict, error) {
	if img.OCIPath == "" {
		return policy.Verdict{}, fmt.Errorf("grype scan: empty OCI path for image")
	}
	rep, err := p.runner.Scan(ctx, img.OCIPath)
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("grype scan: %w", err)
	}
	min := severityRank[strings.ToUpper(p.threshold)]
	var reasons []string
	for _, f := range rep.Findings {
		rank, known := severityRank[strings.ToUpper(f.Severity)]
		if !known {
			// Unrecognized severity: fail closed — never silently drop a finding.
			reasons = append(reasons, fmt.Sprintf("%s (unrecognized severity %q) in %s %s", f.CVE, f.Severity, f.Pkg, f.Version))
			continue
		}
		if rank >= min {
			reasons = append(reasons, fmt.Sprintf("%s (%s) in %s %s", f.CVE, f.Severity, f.Pkg, f.Version))
		}
	}
	return policy.Verdict{
		Passed:           len(reasons) == 0,
		Reasons:          reasons,
		Findings:         rep.Findings,
		ScannerDBVersion: rep.DBVersion,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policies/grype/ -v`
Expected: PASS (all Task 1 + Task 2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/policies/grype/grype.go internal/policies/grype/grype_test.go
git commit -m "feat(grype): policy with grype severity ranking"
```

---

## Task 3: Grype exec runner (`exec_runner.go`)

**Files:**
- Create: `internal/policies/grype/exec_runner.go`
- Create: `internal/policies/grype/exec_runner_test.go`

**Interfaces:**
- Consumes: `Runner`, `ParseReport` (Tasks 1-2).
- Produces: `func NewExecRunner(binary string) Runner`.

- [ ] **Step 1: Write the failing test**

```go
package grype

import (
	"context"
	"strings"
	"testing"
)

func TestExecRunnerBuildsGrypeCommand(t *testing.T) {
	er := &execRunner{
		binary: "grype",
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "grype" {
				t.Errorf("binary = %q, want grype", name)
			}
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "-o json") {
				t.Errorf("args missing -o json: %v", args)
			}
			if !strings.Contains(joined, "/oci/path") {
				t.Errorf("args missing oci path: %v", args)
			}
			return []byte(`{"matches":[],"descriptor":{"db":{"schemaVersion":5,"built":"2026-07-16T00:00:00Z"}}}`), nil
		},
	}
	rep, err := er.Scan(context.Background(), "/oci/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.DBVersion == "" {
		t.Errorf("DBVersion should be populated, got empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policies/grype/ -run TestExecRunner -v`
Expected: FAIL — `undefined: execRunner`.

- [ ] **Step 3: Write the exec runner**

```go
package grype

import (
	"context"
	"fmt"
	"os/exec"
)

type execFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

type execRunner struct {
	binary string
	run    execFunc
}

// NewExecRunner returns a Runner that shells out to the grype binary.
func NewExecRunner(binary string) Runner {
	return &execRunner{
		binary: binary,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		},
	}
}

func (e *execRunner) Scan(ctx context.Context, ociPath string) (Report, error) {
	// Grype scans the assembled OCI layout directory. "-q" silences the
	// progress UI so stdout is clean JSON; "-o json" selects native output.
	out, err := e.run(ctx, e.binary, ociPath, "-o", "json", "-q")
	if err != nil {
		return Report{}, fmt.Errorf("run grype: %w", err)
	}
	return ParseReport(out)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policies/grype/ -v`
Expected: PASS (all grype tests).

- [ ] **Step 5: Delete the trivy package**

```bash
git rm -r internal/policies/trivy
```

- [ ] **Step 6: Verify the trivy package is gone and grype compiles**

Run: `go build ./internal/policies/grype/ && test ! -d internal/policies/trivy && echo OK`
Expected: `OK`

- [ ] **Step 7: Commit**

```bash
git add internal/policies/grype/exec_runner.go internal/policies/grype/exec_runner_test.go
git commit -m "feat(grype): exec runner; remove trivy package"
```

---

## Task 4: Rename Result.TrivyDBVersion → ScannerDBVersion (policy + engine)

**Files:**
- Modify: `internal/policy/policy.go:67`
- Modify: `internal/policy/engine.go:38-39`

**Interfaces:**
- Produces: `policy.Result.ScannerDBVersion string` (was `TrivyDBVersion`).

- [ ] **Step 1: Rename the field in policy.go**

In `internal/policy/policy.go`, change the `Result` struct field:

```go
// Result is the aggregate outcome of running all policies.
type Result struct {
	Passed           bool
	Verdicts         map[string]Verdict
	Findings         []Finding
	ScannerDBVersion string
	Age              *AgeInfo // nil when the age policy is disabled/absent
}
```

- [ ] **Step 2: Update engine.go to the identity assignment**

In `internal/policy/engine.go`, the mapping becomes a same-named assignment:

```go
		if v.ScannerDBVersion != "" {
			res.ScannerDBVersion = v.ScannerDBVersion
		}
```

- [ ] **Step 3: Build to find all consumers**

Run: `go build ./... 2>&1 | head -30`
Expected: compile errors ONLY in files still reading `res.TrivyDBVersion` / `Result{}.TrivyDBVersion` — these are fixed in Tasks 5-6. (If the only errors are in `internal/ingress/docker/outcome.go`, `internal/audit`, `internal/dashboard`, that is expected. Do not fix them here.)

- [ ] **Step 4: Commit**

```bash
git add internal/policy/policy.go internal/policy/engine.go
git commit -m "refactor(policy): rename Result.TrivyDBVersion to ScannerDBVersion"
```

---

## Task 5: Rename audit field + ClickHouse column (schema + Go)

**Files:**
- Modify: `internal/audit/audit.go:23`
- Modify: `internal/audit/clickhouse.go:117,120`
- Modify: `internal/audit/dashboard_reader.go:54`
- Modify: `internal/audit/dashboard_queries.go` (SELECT lists at ~lines 65-66, 72-73, 114-115)
- Modify: `internal/audit/schema.sql:12`
- Modify: `internal/ingress/docker/outcome.go:129`

**Interfaces:**
- Consumes: `policy.Result.ScannerDBVersion` (Task 4).
- Produces: `audit.Decision.ScannerDBVersion`, `audit.DecisionHeader.ScannerDBVersion`; ClickHouse column `scanner_db_version`.

- [ ] **Step 1: Rename the struct fields**

In `internal/audit/audit.go`, `Decision` struct: rename `TrivyDBVersion string` → `ScannerDBVersion string`.
In `internal/audit/dashboard_reader.go`, `DecisionHeader` struct: rename `TrivyDBVersion string` → `ScannerDBVersion string`.

- [ ] **Step 2: Update the INSERT in clickhouse.go**

In `internal/audit/clickhouse.go` `WriteDecision`, change the column list and the bound value:
- Column list: replace `trivy_db_version` with `scanner_db_version`.
- Value: replace `d.TrivyDBVersion` with `d.ScannerDBVersion`.

```go
	return c.conn.Exec(ctx, `
INSERT INTO gate_decisions
(ts, push_id, image_repo, image_tag, image_digest, identity, passed, failed_policies, reasons, base_image_id, scanner_db_version, duration_ms, image_created, image_age_days, image_age_threshold_days, image_age_known)
VALUES (now64(3), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.PushID, d.Repo, d.Tag, d.Digest, d.Identity, d.Passed,
		d.FailedPolicies, d.Reasons, d.BaseImageID, d.ScannerDBVersion, d.DurationMS,
		d.ImageCreated, d.ImageAgeDays, d.ImageAgeThresholdDays, d.ImageAgeKnown)
```

- [ ] **Step 3: Update the SELECTs in dashboard_queries.go**

In `internal/audit/dashboard_queries.go`, both `DecisionHeaderByPush` and `DecisionHeaderByRef` SELECT `... base_image_id, trivy_db_version, ...`. Replace `trivy_db_version` with `scanner_db_version` in each SELECT column list (there are 3 occurrences: push query, ref query, ref-fallback query). The `scanHeader` scan target `&h.TrivyDBVersion` becomes `&h.ScannerDBVersion`.

- [ ] **Step 4: Update outcome.go assignment**

In `internal/ingress/docker/outcome.go`, the `audit.Decision{...}` literal sets `TrivyDBVersion: res.TrivyDBVersion`. Change to:

```go
		ScannerDBVersion: res.ScannerDBVersion,
```

- [ ] **Step 5: Update schema.sql (column rename + severity enum extension)**

In `internal/audit/schema.sql`:
- In the `CREATE TABLE gate_decisions` body, rename `trivy_db_version String,` → `scanner_db_version String,`.
- In the `CREATE TABLE vulnerability_findings` body, extend the severity enum to include NEGLIGIBLE (Grype emits it; the current enum lacks it, so a Negligible finding would fail to insert):

```sql
    severity Enum8('UNKNOWN'=0,'NEGLIGIBLE'=1,'LOW'=2,'MEDIUM'=3,'HIGH'=4,'CRITICAL'=5),
```

- Add online-ALTER lines alongside the existing age-column ALTERs so existing deployments converge:

```sql
-- Online ALTER for existing deployments: scanner-agnostic DB-version column.
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS scanner_db_version String;
-- Grype emits Negligible; extend the findings severity enum to accept it.
ALTER TABLE vulnerability_findings MODIFY COLUMN severity Enum8('UNKNOWN'=0,'NEGLIGIBLE'=1,'LOW'=2,'MEDIUM'=3,'HIGH'=4,'CRITICAL'=5);
```

Note: the `MODIFY COLUMN` enum extension is backward-compatible — existing values 0-4 keep their labels; only the new `NEGLIGIBLE=1`... wait, verify: the OLD enum maps `LOW=1`, the NEW maps `NEGLIGIBLE=1`, `LOW=2`. **This renumbers existing values** and is NOT safe as a bare MODIFY on populated data. Instead, preserve existing numeric assignments and append NEGLIGIBLE at an unused index:

```sql
    severity Enum8('UNKNOWN'=0,'LOW'=1,'MEDIUM'=2,'HIGH'=3,'CRITICAL'=4,'NEGLIGIBLE'=5),
```
```sql
ALTER TABLE vulnerability_findings MODIFY COLUMN severity Enum8('UNKNOWN'=0,'LOW'=1,'MEDIUM'=2,'HIGH'=3,'CRITICAL'=4,'NEGLIGIBLE'=5);
```
This keeps every existing row's stored byte valid and only adds `NEGLIGIBLE=5`. Use THIS form in both `schema.sql` and the runbook. (The Go severity *ranking* order in Task 2 is independent of these enum byte values — ranking stays Unknown<Negligible<Low<Medium<High<Critical.)

- [ ] **Step 6: Build and run audit tests**

Run: `go build ./internal/audit/ ./internal/ingress/... && go test ./internal/audit/`
Expected: build OK; audit unit tests PASS (integration tests are `//go:build integration`, skipped here).

- [ ] **Step 7: Commit**

```bash
git add internal/audit/ internal/ingress/docker/outcome.go
git commit -m "refactor(audit): rename trivy_db_version to scanner_db_version"
```

---

## Task 6: Rename dashboard field + report label

**Files:**
- Modify: `internal/dashboard/view.go:56`
- Modify: `internal/dashboard/data.go:87`
- Modify: `internal/dashboard/templates/report.html:7`

**Interfaces:**
- Consumes: `audit.DecisionHeader.ScannerDBVersion` (Task 5).
- Produces: `dashboard.ReportVM.ScannerDBVersion`.

- [ ] **Step 1: Rename the VM field**

In `internal/dashboard/view.go`, the `ReportVM` field list has `BaseImageID, TrivyDBVersion string`. Rename to `BaseImageID, ScannerDBVersion string`.

- [ ] **Step 2: Update data.go mapping**

In `internal/dashboard/data.go`, the `ReportVM{...}` literal sets `TrivyDBVersion: hdr.TrivyDBVersion`. Change to `ScannerDBVersion: hdr.ScannerDBVersion`.

- [ ] **Step 3: Update the template label**

In `internal/dashboard/templates/report.html` line 7, replace `trivy {{.VM.TrivyDBVersion}}` with `scanner {{.VM.ScannerDBVersion}}`.

- [ ] **Step 4: Build and test dashboard**

Run: `go build ./internal/dashboard/ && go test ./internal/dashboard/`
Expected: build OK; tests PASS (fix any `templates_test.go` / `data_test.go` assertions still referencing `TrivyDBVersion` or the old label — rename them to match).

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/
git commit -m "refactor(dashboard): rename TrivyDBVersion to ScannerDBVersion + report label"
```

---

## Task 7: Config Trivy → Grype

**Files:**
- Modify: `internal/config/config.go:13,24-26,120-121,204-205`
- Modify: `internal/config/config_test.go` (any `Trivy`/`trivy` references)
- Modify: `charts/merlin/templates/configmap.yaml`
- Modify: `charts/merlin/values.yaml`

**Interfaces:**
- Produces: `config.Config.Grype GrypeConfig`; `GrypeConfig{ SeverityThreshold string }` with yaml key `grype.severity_threshold`.

- [ ] **Step 1: Rename the config struct + field**

In `internal/config/config.go`:
- `Config` field: `Trivy TrivyConfig \`yaml:"trivy"\`` → `Grype GrypeConfig \`yaml:"grype"\``.
- Type: `type TrivyConfig struct { SeverityThreshold string \`yaml:"severity_threshold"\` }` → `type GrypeConfig struct { SeverityThreshold string \`yaml:"severity_threshold"\` }`.
- Default (line ~120): `if c.Trivy.SeverityThreshold == "" { c.Trivy.SeverityThreshold = "CRITICAL" }` → `c.Grype...`.
- Validation (line ~204): `if !validSeverities[c.Trivy.SeverityThreshold]` → `c.Grype.SeverityThreshold`, and the error message text `trivy.severity_threshold` → `grype.severity_threshold`. Keep the valid-severity set as-is (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL) UNLESS you also want NEGLIGIBLE selectable as a threshold — add `NEGLIGIBLE` to `validSeverities` so the config can express it (grype supports it). Add it.

- [ ] **Step 2: Update config_test.go**

Search `internal/config/config_test.go` for `Trivy`/`trivy` and rename to `Grype`/`grype`. If a test asserts the validation error string, update it to `grype.severity_threshold`. If a test builds YAML with `trivy:`, change to `grype:`.

- [ ] **Step 3: Update helm config**

In `charts/merlin/templates/configmap.yaml`, rename the `trivy:` config block key to `grype:` (keep `severity_threshold` sub-key). In `charts/merlin/values.yaml`, rename any `trivy:`/`trivy.severityThreshold` value to `grype:` equivalent.

Verify: `grep -rn "trivy" charts/` returns nothing.

- [ ] **Step 4: Build and test config**

Run: `go build ./internal/config/ && go test ./internal/config/`
Expected: build OK, tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/ charts/merlin/
git commit -m "refactor(config): rename trivy config to grype"
```

---

## Task 8: Wire grype in app.go

**Files:**
- Modify: `internal/app/app.go:26,50,54,229,233`

**Interfaces:**
- Consumes: `grype.New`, `grype.NewExecRunner` (Tasks 1-3); `cfg.Grype.SeverityThreshold` (Task 7).

- [ ] **Step 1: Swap the import**

In `internal/app/app.go`, replace `"github.com/merlin-gate/merlin/internal/policies/trivy"` with `"github.com/merlin-gate/merlin/internal/policies/grype"`.

- [ ] **Step 2: Swap both construction sites**

At both locations (~line 50 and ~line 229), replace:

```go
	trivyPolicy := trivy.New(trivy.NewExecRunner("trivy"), cfg.Trivy.SeverityThreshold)
	...
	engine := policy.NewEngine(trivyPolicy, basePolicy, agePolicy)
```

with:

```go
	grypePolicy := grype.New(grype.NewExecRunner("grype"), cfg.Grype.SeverityThreshold)
	...
	engine := policy.NewEngine(grypePolicy, basePolicy, agePolicy)
```

- [ ] **Step 3: Build**

Run: `go build ./internal/app/`
Expected: OK.

- [ ] **Step 4: Commit**

```bash
git add internal/app/app.go
git commit -m "refactor(app): wire grype policy in place of trivy"
```

---

## Task 9: Metrics rename

**Files:**
- Modify: `internal/observability/metrics.go:17,32,35-37,44,57`
- Modify: `internal/observability/metrics_test.go` (any `Trivy`/`trivy` references)

**Interfaces:**
- Produces: metric `merlin_scanner_db_age_days` (was `merlin_trivy_db_age_days`); method `SetScannerDBAgeDays(days float64)` (was `SetTrivyDBAgeDays`).

- [ ] **Step 1: Rename the gauge, metric name, help text, and setter**

In `internal/observability/metrics.go`:
- struct field `trivyDBAge` → `scannerDBAge`.
- `Name: "merlin_trivy_db_age_days"` → `Name: "merlin_scanner_db_age_days"`.
- `Help: "Age of the Trivy vulnerability DB in days."` → `"Age of the scanner vulnerability DB in days."`
- `Help: "Trivy scan duration in seconds."` → `"Scanner scan duration in seconds."`
- `reg.MustRegister(..., m.trivyDBAge, ...)` → `m.scannerDBAge`.
- method `SetTrivyDBAgeDays` → `SetScannerDBAgeDays` (update its body `m.trivyDBAge.Set` → `m.scannerDBAge.Set`).

- [ ] **Step 2: Update callers + test**

Run: `grep -rn "SetTrivyDBAgeDays\|trivyDBAge\|merlin_trivy_db" internal/`
For each hit outside metrics.go (and in metrics_test.go), rename to the scanner equivalent.

- [ ] **Step 3: Build and test**

Run: `go build ./... && go test ./internal/observability/`
Expected: OK / PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/observability/
git commit -m "refactor(observability): rename trivy metrics to scanner"
```

---

## Task 10: Sweep remaining trivy references in tests + build green

**Files:**
- Modify: any remaining `*_test.go` referencing `trivy`/`Trivy`/`TrivyDBVersion` (app, ingress/docker, dashboard, audit integration).

**Interfaces:** none new.

- [ ] **Step 1: Find all remaining references**

Run: `grep -rln "trivy\|Trivy\|TrivyDBVersion" internal cmd`
Expected: a list of test files (and possibly integration tests) still using old names.

- [ ] **Step 2: Rename each reference**

For each file, apply the mechanical rename:
- `TrivyDBVersion` → `ScannerDBVersion`
- `cfg.Trivy` / `config.TrivyConfig` → `cfg.Grype` / `config.GrypeConfig`
- import/use of `policies/trivy` → `policies/grype`, `trivy.New` → `grype.New`
- any `trivy_db_version` string literal in test SQL/JSON → `scanner_db_version`
- test severity fixtures using trivy upper-case (`"CRITICAL"`) are still valid for grype's ranking (upper-cased on lookup); leave finding-severity strings as-is unless a test specifically asserts grype title-case.

- [ ] **Step 3: Full build + race test + integration vet**

Run:
```bash
go build ./... && go test -race ./... && go vet -tags integration ./...
```
Expected: build OK; all tests PASS; vet clean. If an integration test file references the renamed column, update its SQL/fixtures to `scanner_db_version`.

- [ ] **Step 4: Confirm no trivy references remain**

Run: `grep -rin "trivy" internal cmd charts | grep -v "_test.go:.*// historical" || echo "CLEAN"`
Expected: `CLEAN` (or only intentional historical comments).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: sweep remaining trivy references to grype"
```

---

## Task 11: Dockerfile — ship grype binary

**Files:**
- Modify: `Dockerfile:22-34`

**Interfaces:** none (runtime binary on PATH as `grype`).

- [ ] **Step 1: Replace the trivy stage + copy**

In `Dockerfile`, replace lines 22-34 (the trivy stage source, comments, and COPY) with the grype equivalent:

```dockerfile
# Grype binary source: copy the static grype binary from the official image.
FROM anchore/grype:v0.98.0 AS grype

FROM ${RUNTIME_BASE}
# Chainguard base already runs as nonroot (uid 65532) and ships CA certs.
COPY --from=build /out/merlin /usr/local/bin/merlin
# Merlin shells out to `grype` at runtime for scanning. Without grype on PATH,
# every scan fails infra-closed → 500. Copy the grype binary from the official image.
# NOTE: grype needs its vulnerability database. On first run it downloads the DB
# from anchore's endpoints (or via `grype db update`). The pod needs network
# egress for the DB; cache dir is GRYPE_DB_CACHE_DIR (default ~/.cache/grype/db).
COPY --from=grype /grype /usr/local/bin/grype
```

Keep the existing `USER 65532:65532`, `ENV MERLIN_MODE=... MERLIN_CONFIG=...`, and `ENTRYPOINT ["/usr/local/bin/merlin"]` lines that follow.

Note: verify the grype binary path inside `anchore/grype:v0.98.0` is `/grype` (it is for the official image). If a build shows it missing, inspect with `docker run --rm --entrypoint sh anchore/grype:v0.98.0 -c 'command -v grype'` and adjust the COPY source.

- [ ] **Step 2: Build the image (amd64, FIPS base per current deploy)**

Run:
```bash
docker buildx build --platform linux/amd64 \
  --build-arg RUNTIME_BASE=dev-registry.c3.ai/c3.ai/chainguard-base-fips:latest-202607031236 \
  -t merlin:grype-test --load .
```
Expected: build succeeds; final stage copies both `/usr/local/bin/merlin` and `/usr/local/bin/grype`.

- [ ] **Step 3: Smoke-test grype is present and runnable in the image**

Run:
```bash
docker run --rm --platform linux/amd64 --entrypoint /usr/local/bin/grype merlin:grype-test version
```
Expected: prints grype version (confirms the binary runs on the FIPS base).

- [ ] **Step 4: Commit**

```bash
git add Dockerfile
git commit -m "build(grype): ship grype binary in place of trivy"
```

---

## Task 12: Full verification gate

**Files:** none (verification only).

- [ ] **Step 1: Whole build, race tests, integration vet**

Run:
```bash
go build ./... && go test -race ./... && go vet -tags integration ./...
```
Expected: all green.

- [ ] **Step 2: Confirm trivy is fully gone from source**

Run: `grep -rin "trivy" internal cmd charts Dockerfile && echo "FOUND (review)" || echo "CLEAN"`
Expected: `CLEAN`.

- [ ] **Step 3: Confirm the grype package is the only scanner**

Run: `ls internal/policies/`
Expected: `baseimage  grype  imageage` (no `trivy`).

- [ ] **Step 4: Final commit if the sweep changed anything**

```bash
git add -A && git commit -m "chore(grype): finalize trivy->grype swap" || echo "nothing to commit"
```

---

## Deployment & migration runbook (post-merge, operator-run)

Not code steps — run these when deploying the built image, in order (expand/contract):

1. **Expand:** add the new column and extend the findings severity enum (both safe alongside the old binary):
   ```sql
   ALTER TABLE merlin.gate_decisions ADD COLUMN IF NOT EXISTS scanner_db_version String;
   ALTER TABLE merlin.vulnerability_findings MODIFY COLUMN severity Enum8('UNKNOWN'=0,'LOW'=1,'MEDIUM'=2,'HIGH'=3,'CRITICAL'=4,'NEGLIGIBLE'=5);
   ```
   (The updated `schema.sql` also does this on bootstrap. The enum change only appends NEGLIGIBLE=5, preserving existing rows.)
2. **Deploy** the grype image (build → push `dev-registry.c3.ai/merlin:<sha>` → `helm upgrade --set image.tag=<sha> --set image.pullPolicy=Always` → rollout restart → verify 2/2 READY, `/v2/` responds).
3. **Verify** a live push records `scanner_db_version` (run a gate push; confirm a fresh `gate_decisions` row has it populated).
4. **Contract:** once healthy, drop the old column:
   `ALTER TABLE merlin.gate_decisions DROP COLUMN IF EXISTS trivy_db_version;`

---

## Self-Review Notes

- **Spec coverage:** package rename (Tasks 1-3), config (Task 7), Dockerfile (Task 11), schema rename + field threading (Tasks 4-6), metrics (Task 9), test fallout (Task 10), expand/contract migration (runbook). All spec sections covered.
- **Enum gap (verified + resolved):** `vulnerability_findings.severity` is a ClickHouse `Enum8('LOW'=1,'MEDIUM'=2,'HIGH'=3,'CRITICAL'=4,'UNKNOWN'=0)` with no NEGLIGIBLE, but Grype emits `Negligible`. Resolved in Task 1 (parser upper-cases severity → stored labels match the enum) + Task 5 (append `NEGLIGIBLE=5` to the enum, preserving existing row bytes). Verified the append form does not renumber existing values.
- **Severity casing:** parser stores UPPER-CASE; ranking map keyed upper-case; threshold upper-cased on lookup. Consistent across Tasks 1, 2, 5.
- **Type consistency:** `ScannerDBVersion` used identically in `policy.Result` (T4), `audit.Decision`/`DecisionHeader` (T5), `dashboard.ReportVM` (T6); column `scanner_db_version` in INSERT (T5 clickhouse.go) matches SELECTs (T5 dashboard_queries.go) matches schema (T5 schema.sql).
