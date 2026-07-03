# Image-Age Compliance Gate Policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a blocking image-age policy to Merlin's in-band manifest-PUT gate that rejects an image whose OCI config `created` timestamp is older than a per-tenant configurable threshold (default 60 days), and surface the age result in the scan report, response header, audit trail, and dashboard.

**Architecture:** Age is extracted once during image assembly from the config blob Merlin already fetches, and carried on `policy.StagedImage.Created`. A new `imageage` policy (registered alongside trivy/baseimage in the single shared engine) reads `StagedImage.Created` + `StagedImage.Prefix`, applies the per-tenant threshold, and packs a structured `AgeInfo` onto its `Verdict`. The engine forwards `Verdict.Age` to `Result.Age` (mirroring how it already forwards `Findings`/`ScannerDBVersion`). From `Result.Age` the outcome adapter records age to ClickHouse and the report/dashboard/header read it back.

**Tech Stack:** Go 1.26, standard `go test` (table-driven, `-race`), ClickHouse (audit), `gopkg.in/yaml.v3` (config). No new dependencies.

## Global Constraints

- Module path: `github.com/merlin-gate/merlin`. Go 1.26.
- `gofmt`/`goimports` mandatory; wrap errors with `%w` and context.
- Tests are table-driven; run touched packages with `go test -race ./internal/...`.
- Accept interfaces, return structs; keep interfaces small.
- Age policy is **fail-closed**: an image whose `created` cannot be determined is REJECTED (400) with a reason clearly distinct from "too old" (spec §3.5).
- Age threshold default is **60** days; the policy is enable/disable-able **per tenant** (spec §3.3).
- **Report format change (interpreting spec §5 + age-spec §3.4):** `GET /reports/<ref>` changes from a bare findings array to an envelope `{"age": {...}|null, "findings": [...]}`. This is a deliberate, spec-driven breaking change to the report body; `docs/USAGE.md` and `docs/CI.md` are updated in the final task.
- "Unknown age" is represented in ClickHouse by `image_created = 0` (epoch); readers key unknown off `image_created` being zero, never off the age integer.

---

### Task 1: Extract image creation time during assembly

**Files:**
- Modify: `internal/policy/policy.go` (add two fields to `StagedImage`)
- Create: `internal/staging/created.go`
- Create: `internal/staging/created_test.go`
- Modify: `internal/staging/assemble.go` (parse config `created`, set on returned `StagedImage`)

**Interfaces:**
- Produces: `policy.StagedImage.Created time.Time` (zero = unknown) and `policy.StagedImage.Prefix string` (tenant prefix, set later by the ingress handler in Task 7).
- Produces: `staging.parseImageCreated(configRaw []byte) (time.Time, error)` (unexported).

- [ ] **Step 1: Add fields to `StagedImage`**

In `internal/policy/policy.go`, add `"time"` to imports and extend the struct:

```go
// StagedImage is the assembled image a policy evaluates.
type StagedImage struct {
	Repo    string
	Tag     string
	Digest  string
	FSPath  string // assembled root filesystem directory (for os-release reads)
	OCIPath string // on-disk OCI layout (for Trivy)
	// Created is the image config's "created" timestamp (RFC3339). Zero value means
	// the timestamp could not be determined; the image-age policy fails closed on it.
	Created time.Time
	// Prefix is the resolved tenant prefix (set by the ingress handler). The image-age
	// policy uses it to select the per-tenant age rule.
	Prefix string
}
```

- [ ] **Step 2: Write the failing test for `parseImageCreated`**

Create `internal/staging/created_test.go`:

```go
package staging

import (
	"testing"
	"time"
)

func TestParseImageCreated(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    time.Time
		wantErr bool
	}{
		{
			name:   "rfc3339",
			config: `{"created":"2026-04-20T10:31:00Z","architecture":"amd64"}`,
			want:   time.Date(2026, 4, 20, 10, 31, 0, 0, time.UTC),
		},
		{
			name:   "rfc3339nano",
			config: `{"created":"2026-04-20T10:31:00.123456789Z"}`,
			want:   time.Date(2026, 4, 20, 10, 31, 0, 123456789, time.UTC),
		},
		{name: "missing created field", config: `{"architecture":"amd64"}`, wantErr: true},
		{name: "empty created", config: `{"created":""}`, wantErr: true},
		{name: "malformed json", config: `{not json`, wantErr: true},
		{name: "unparseable timestamp", config: `{"created":"not-a-time"}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseImageCreated([]byte(tt.config))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (time=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/staging/ -run TestParseImageCreated -v`
Expected: FAIL — `undefined: parseImageCreated`.

- [ ] **Step 4: Implement `parseImageCreated`**

Create `internal/staging/created.go`:

```go
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/staging/ -run TestParseImageCreated -v`
Expected: PASS (all sub-tests).

- [ ] **Step 6: Wire extraction into `Assemble`**

In `internal/staging/assemble.go`, add `"log"` to imports. Replace the config-blob block (currently lines 36–46) so the parsed timestamp is captured, and set it on the returned struct.

Change the config block to capture `created`:

```go
	// The config blob (when present) goes into the OCI layout verbatim — it is
	// JSON, not a filesystem layer, so it must never be tar-extracted.
	var created time.Time
	if mr.ConfigDigest != "" {
		raw, err := s.fetchVerified(ctx, mr.ConfigDigest)
		if err != nil {
			return policy.StagedImage{}, err
		}
		if err := writeOCIBlob(ociPath, mr.ConfigDigest, raw); err != nil {
			return policy.StagedImage{}, err
		}
		// Extract the creation timestamp for the image-age policy. A parse failure is
		// non-fatal here (leaves created zero); the age policy fails closed on unknown.
		if c, perr := parseImageCreated(raw); perr != nil {
			log.Printf("assemble %s/%s: could not read image created timestamp: %v", mr.Repo, mr.Ref, perr)
		} else {
			created = c
		}
	}
```

And extend the returned struct (currently lines 82–87):

```go
	return policy.StagedImage{
		Repo:    mr.Repo,
		Tag:     mr.Ref,
		OCIPath: ociPath,
		FSPath:  rootfs,
		Created: created,
	}, nil
```

Add `"time"` to the `internal/staging/assemble.go` import block.

- [ ] **Step 7: Write the failing test that `Assemble` sets `Created`**

Add to `internal/staging/created_test.go`:

```go
import (
	"context"
	// (add alongside existing imports: testing, time)
)

func TestAssembleSetsCreated(t *testing.T) {
	created := "2026-05-01T12:00:00Z"
	config := []byte(`{"created":"` + created + `","architecture":"amd64","rootfs":{"type":"layers","diff_ids":[]}}`)
	cfgDigest := digestOf(config)

	store, mr, scratch := newAssembleFixture(t, config, cfgDigest)
	img, err := store.Assemble(context.Background(), mr, scratch)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	want := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if !img.Created.Equal(want) {
		t.Fatalf("Created = %v, want %v", img.Created, want)
	}
}
```

**Reuse the existing staging test helpers.** Inspect `internal/staging/assemble_test.go` (or the nearest existing assembly test) for the in-memory blob-store fixture and digest helper already used there; implement `newAssembleFixture` and `digestOf` as thin wrappers over those existing helpers (do NOT introduce a second fake blob store). If no assembly test exists, build the fixture from the in-memory `BlobStore`/`SessionStore` fakes used in `internal/staging`'s other `_test.go` files: stage the config blob under `blobKey(cfgDigest)`, construct `ManifestRef{Repo:"app", Ref:"v1", ConfigDigest: cfgDigest}` with no layers, and use a `t.TempDir()` scratch dir.

- [ ] **Step 8: Run tests to verify they pass**

Run: `go test ./internal/staging/ -run 'TestParseImageCreated|TestAssembleSetsCreated' -race -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
gofmt -w internal/policy/policy.go internal/staging/created.go internal/staging/created_test.go internal/staging/assemble.go
git add internal/policy/policy.go internal/staging/created.go internal/staging/created_test.go internal/staging/assemble.go
git commit -m "feat(staging): extract image config created timestamp during assembly"
```

---

### Task 2: Carry age result through policy engine

**Files:**
- Modify: `internal/policy/policy.go` (add `AgeInfo`; add `Age` to `Verdict` and `Result`)
- Modify: `internal/policy/engine.go` (forward `Verdict.Age` → `Result.Age`)
- Modify: `internal/policy/engine_test.go` (verify forwarding)

**Interfaces:**
- Produces: `policy.AgeInfo{Created time.Time; AgeDays int; ThresholdDays int; Compliant bool; Known bool}`.
- Produces: `policy.Verdict.Age *AgeInfo` (set only by the age policy; nil otherwise).
- Produces: `policy.Result.Age *AgeInfo` (set by the engine from the first verdict that carries one).

- [ ] **Step 1: Add `AgeInfo` and the `Age` fields**

In `internal/policy/policy.go`, add the struct and fields:

```go
// AgeInfo is the image-age policy's structured result, carried back on the
// Verdict and surfaced on Result so the outcome/report/audit can record it.
// Known=false means the image's created timestamp could not be determined
// (Created is then the zero value and Compliant is false — fail closed).
type AgeInfo struct {
	Known         bool
	Created       time.Time
	AgeDays       int
	ThresholdDays int
	Compliant     bool
}
```

Add `Age *AgeInfo` to `Verdict`:

```go
type Verdict struct {
	Passed           bool
	Reasons          []string
	Findings         []Finding
	ScannerDBVersion string
	Age              *AgeInfo // set by the image-age policy; nil for other policies
}
```

Add `Age *AgeInfo` to `Result`:

```go
type Result struct {
	Passed         bool
	Verdicts       map[string]Verdict
	Findings       []Finding
	TrivyDBVersion string
	Age            *AgeInfo // nil when the age policy is disabled/absent
}
```

- [ ] **Step 2: Write the failing test for engine forwarding**

Add to `internal/policy/engine_test.go` (match the existing fake-policy pattern in that file; the fake below is self-contained if none exists):

```go
type agePolicyStub struct{ age *AgeInfo }

func (agePolicyStub) Name() string { return "imageage" }
func (p agePolicyStub) Evaluate(_ context.Context, _ StagedImage) (Verdict, error) {
	return Verdict{Passed: p.age.Compliant, Age: p.age}, nil
}

func TestEngineForwardsAge(t *testing.T) {
	age := &AgeInfo{Known: true, AgeDays: 12, ThresholdDays: 60, Compliant: true}
	e := NewEngine(agePolicyStub{age: age})
	res, err := e.Run(context.Background(), StagedImage{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Age == nil || res.Age.AgeDays != 12 || !res.Age.Compliant {
		t.Fatalf("Result.Age not forwarded: %+v", res.Age)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestEngineForwardsAge -v`
Expected: FAIL — `res.Age` is nil (`Result.Age not forwarded`).

- [ ] **Step 4: Forward `Verdict.Age` in the engine**

In `internal/policy/engine.go`, inside the `for _, p := range e.policies` loop, after the existing `res.Findings = append(...)` / `ScannerDBVersion` handling, add:

```go
		if v.Age != nil {
			res.Age = v.Age
		}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/policy/ -run TestEngineForwardsAge -race -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/policy/policy.go internal/policy/engine.go internal/policy/engine_test.go
git add internal/policy/policy.go internal/policy/engine.go internal/policy/engine_test.go
git commit -m "feat(policy): carry image-age result through engine to Result"
```

---

### Task 3: The image-age policy

**Files:**
- Create: `internal/policies/imageage/age.go` (pure day math)
- Create: `internal/policies/imageage/age_test.go`
- Create: `internal/policies/imageage/imageage.go` (the policy)
- Create: `internal/policies/imageage/imageage_test.go`

**Interfaces:**
- Consumes: `policy.StagedImage.Created`, `policy.StagedImage.Prefix`, `policy.AgeInfo`, `policy.Verdict`.
- Produces: `imageage.Rule{Enabled bool; ThresholdDays int}`.
- Produces: `imageage.New(defaultRule Rule, perTenant map[string]Rule) *Policy` — implements `policy.Policy` with `Name() == "imageage"`.
- Produces: `imageage.ageDays(created, now time.Time) int` (unexported, floor, clamped ≥ 0).

- [ ] **Step 1: Write the failing test for `ageDays`**

Create `internal/policies/imageage/age_test.go`:

```go
package imageage

import (
	"testing"
	"time"
)

func TestAgeDays(t *testing.T) {
	now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		created time.Time
		want    int
	}{
		{"same instant", now, 0},
		{"one day ago", now.Add(-24 * time.Hour), 1},
		{"sixty days ago", now.Add(-60 * 24 * time.Hour), 60},
		{"partial day floors down", now.Add(-47 * time.Hour), 1},
		{"future clamps to zero", now.Add(48 * time.Hour), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ageDays(tt.created, now); got != tt.want {
				t.Fatalf("ageDays = %d, want %d", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policies/imageage/ -run TestAgeDays -v`
Expected: FAIL — `undefined: ageDays`.

- [ ] **Step 3: Implement `ageDays`**

Create `internal/policies/imageage/age.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policies/imageage/ -run TestAgeDays -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for the policy**

Create `internal/policies/imageage/imageage_test.go`:

```go
package imageage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/policy"
)

func fixedNow() time.Time { return time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC) }

func newTestPolicy(def Rule, per map[string]Rule) *Policy {
	p := New(def, per)
	p.now = fixedNow // deterministic
	return p
}

func TestFreshImagePasses(t *testing.T) {
	p := newTestPolicy(Rule{Enabled: true, ThresholdDays: 60}, nil)
	v, err := p.Evaluate(context.Background(), policy.StagedImage{
		Created: fixedNow().Add(-10 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !v.Passed || v.Age == nil || !v.Age.Compliant || v.Age.AgeDays != 10 {
		t.Fatalf("expected compliant pass, got passed=%v age=%+v", v.Passed, v.Age)
	}
}

func TestOldImageRejected(t *testing.T) {
	p := newTestPolicy(Rule{Enabled: true, ThresholdDays: 60}, nil)
	created := fixedNow().Add(-74 * 24 * time.Hour)
	v, err := p.Evaluate(context.Background(), policy.StagedImage{Created: created})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Passed {
		t.Fatal("expected reject for 74-day-old image")
	}
	if v.Age == nil || v.Age.Compliant || v.Age.AgeDays != 74 || v.Age.ThresholdDays != 60 {
		t.Fatalf("age info wrong: %+v", v.Age)
	}
	if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "age 74d exceeds max 60d") {
		t.Fatalf("reason wrong: %v", v.Reasons)
	}
}

func TestBoundaryEqualsThresholdPasses(t *testing.T) {
	p := newTestPolicy(Rule{Enabled: true, ThresholdDays: 60}, nil)
	v, _ := p.Evaluate(context.Background(), policy.StagedImage{
		Created: fixedNow().Add(-60 * 24 * time.Hour),
	})
	if !v.Passed {
		t.Fatal("age == threshold must pass (<=)")
	}
}

func TestUnknownCreatedFailsClosed(t *testing.T) {
	p := newTestPolicy(Rule{Enabled: true, ThresholdDays: 60}, nil)
	v, err := p.Evaluate(context.Background(), policy.StagedImage{}) // zero Created
	if err != nil {
		t.Fatalf("Evaluate must not return infra error for unknown age: %v", err)
	}
	if v.Passed {
		t.Fatal("unknown created must fail closed")
	}
	if v.Age == nil || v.Age.Known {
		t.Fatalf("expected Age.Known=false, got %+v", v.Age)
	}
	if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "could not determine image age") {
		t.Fatalf("expected distinct unknown-age reason, got %v", v.Reasons)
	}
	if strings.Contains(v.Reasons[0], "exceeds max") {
		t.Fatal("unknown-age reason must not read like a too-old verdict")
	}
}

func TestDisabledTenantSkipsGating(t *testing.T) {
	p := newTestPolicy(
		Rule{Enabled: true, ThresholdDays: 60},
		map[string]Rule{"slowmirror": {Enabled: false}},
	)
	// A very old image under a disabled tenant passes and reports no age.
	v, _ := p.Evaluate(context.Background(), policy.StagedImage{
		Prefix:  "slowmirror",
		Created: fixedNow().Add(-999 * 24 * time.Hour),
	})
	if !v.Passed {
		t.Fatal("disabled tenant must not gate on age")
	}
	if v.Age != nil {
		t.Fatalf("disabled tenant must report no age, got %+v", v.Age)
	}
}

func TestPerTenantThresholdOverride(t *testing.T) {
	p := newTestPolicy(
		Rule{Enabled: true, ThresholdDays: 60},
		map[string]Rule{"vendor": {Enabled: true, ThresholdDays: 365}},
	)
	v, _ := p.Evaluate(context.Background(), policy.StagedImage{
		Prefix:  "vendor",
		Created: fixedNow().Add(-200 * 24 * time.Hour),
	})
	if !v.Passed {
		t.Fatal("200d image under 365d tenant threshold must pass")
	}
	if v.Age.ThresholdDays != 365 {
		t.Fatalf("expected threshold 365, got %d", v.Age.ThresholdDays)
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/policies/imageage/ -run 'Image|Boundary|Unknown|Disabled|PerTenant' -v`
Expected: FAIL — `undefined: New`, `Rule`, `Policy`.

- [ ] **Step 7: Implement the policy**

Create `internal/policies/imageage/imageage.go`:

```go
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
			Reasons: []string{"rejected: could not determine image age (image config is missing a readable created timestamp)"},
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
			"rejected: image age %dd exceeds max %dd (created %s)",
			age, rule.ThresholdDays, img.Created.Format(time.RFC3339))},
		Age: info,
	}, nil
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `go test ./internal/policies/imageage/ -race -v`
Expected: PASS (all sub-tests).

- [ ] **Step 9: Commit**

```bash
gofmt -w internal/policies/imageage/
git add internal/policies/imageage/
git commit -m "feat(policy): add image-age gate policy (per-tenant threshold, fail-closed)"
```

---

### Task 4: Image-age configuration

**Files:**
- Modify: `internal/config/config.go` (add `ImageAgeConfig`, top-level + per-tenant, defaults, validation)
- Modify: `internal/config/config_test.go` (defaults + validation cases)

**Interfaces:**
- Produces: `config.ImageAgeConfig{Enabled *bool; ThresholdDays int}`.
- Produces: `config.Config.ImageAge ImageAgeConfig` (deployment default) and `config.TenantConfig.ImageAge *ImageAgeConfig` (per-tenant override; nil = inherit default).

- [ ] **Step 1: Add config types**

In `internal/config/config.go`, add the type and fields:

```go
// ImageAgeConfig configures the image-age gate policy. Enabled is a pointer so an
// unset value can inherit the default (true) rather than defaulting to false.
type ImageAgeConfig struct {
	Enabled       *bool `yaml:"enabled"`
	ThresholdDays int   `yaml:"threshold_days"`
}
```

Add `ImageAge ImageAgeConfig` to `Config` (place it near `Trivy`/`BaseImage`):

```go
	ImageAge  ImageAgeConfig  `yaml:"image_age"`
```

Add `ImageAge *ImageAgeConfig` to `TenantConfig`:

```go
	ImageAge    *ImageAgeConfig  `yaml:"image_age"`
```

- [ ] **Step 2: Apply defaults**

In `applyDefaults()`, add:

```go
	if c.ImageAge.ThresholdDays == 0 {
		c.ImageAge.ThresholdDays = 60
	}
	if c.ImageAge.Enabled == nil {
		enabled := true
		c.ImageAge.Enabled = &enabled
	}
```

- [ ] **Step 3: Validate**

In `validate()`, before `return nil`, add:

```go
	if c.ImageAge.ThresholdDays < 0 {
		return fmt.Errorf("config: image_age.threshold_days must be >= 0")
	}
	for i, t := range c.Tenants {
		if t.ImageAge != nil && t.ImageAge.ThresholdDays < 0 {
			return fmt.Errorf("config: tenants[%d] (%s) image_age.threshold_days must be >= 0", i, t.Prefix)
		}
	}
```

- [ ] **Step 4: Write the failing tests**

Add to `internal/config/config_test.go` (follow the file's existing helper for loading YAML from a temp file — reuse it; do not add a second loader):

```go
func TestImageAgeDefaults(t *testing.T) {
	cfg := loadValidConfig(t) // existing helper that writes+loads a minimal valid config
	if cfg.ImageAge.ThresholdDays != 60 {
		t.Fatalf("default threshold = %d, want 60", cfg.ImageAge.ThresholdDays)
	}
	if cfg.ImageAge.Enabled == nil || !*cfg.ImageAge.Enabled {
		t.Fatalf("default enabled = %v, want true", cfg.ImageAge.Enabled)
	}
}

func TestImageAgeNegativeThresholdRejected(t *testing.T) {
	cfg := minimalValidConfig() // existing helper returning a *Config or YAML string
	cfg.ImageAge.ThresholdDays = -1
	if err := cfg.validate(); err == nil {
		t.Fatal("expected validation error for negative threshold")
	}
}
```

If `config_test.go` has no such helpers, write the minimal valid config inline (a YAML string with `acr.registry_template`, `acr.base_domain`, one full `tenants[]` entry, and `base_image.allowed_ids`) and call `Load` on a temp file, matching the existing tests in that file.

- [ ] **Step 5: Run tests to verify they fail then pass**

Run: `go test ./internal/config/ -run TestImageAge -v`
Expected: initially FAIL (fields undefined), PASS after Steps 1–3.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/config/config.go internal/config/config_test.go
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add image_age policy config (default 60d, per-tenant override)"
```

---

### Task 5: Audit — persist and read back image age

**Files:**
- Modify: `internal/audit/audit.go` (add age fields to `Decision`)
- Modify: `internal/audit/schema.sql` (three new columns + ALTER for existing installs)
- Modify: `internal/audit/clickhouse.go` (`WriteDecision` insert columns/values)
- Modify: `internal/audit/dashboard_reader.go` (age fields on `DecisionHeader`)
- Modify: `internal/audit/dashboard_queries.go` (select + scan age in header queries)
- Modify: `internal/audit/clickhouse_integration_test.go` (round-trip age)

**Interfaces:**
- Consumes: `policy.AgeInfo` (via `Decision`).
- Produces: `audit.Decision.ImageCreated time.Time`, `audit.Decision.ImageAgeDays uint16`, `audit.Decision.ImageAgeThresholdDays uint16`.
- Produces: `audit.DecisionHeader.ImageCreated time.Time`, `.ImageAgeDays uint16`, `.ImageAgeThresholdDays uint16` (unknown ⇔ `ImageCreated.IsZero()`).

- [ ] **Step 1: Add fields to `Decision`**

In `internal/audit/audit.go`, add `"time"` to imports and extend `Decision`:

```go
	// Image-age policy result. ImageCreated is zero when age was not determined /
	// the age policy was disabled (readers treat zero as "unknown").
	ImageCreated          time.Time
	ImageAgeDays          uint16
	ImageAgeThresholdDays uint16
```

- [ ] **Step 2: Update the schema**

In `internal/audit/schema.sql`, add the three columns to the `gate_decisions` CREATE TABLE (after `duration_ms`):

```sql
    duration_ms      UInt32,
    image_created            DateTime64(3) DEFAULT 0,
    image_age_days           UInt16 DEFAULT 0,
    image_age_threshold_days UInt16 DEFAULT 0
```

And append online ALTERs (after the existing `ADD INDEX` statements) so existing deployments migrate non-destructively:

```sql
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_created DateTime64(3) DEFAULT 0;
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_age_days UInt16 DEFAULT 0;
ALTER TABLE gate_decisions ADD COLUMN IF NOT EXISTS image_age_threshold_days UInt16 DEFAULT 0;
```

- [ ] **Step 3: Update `WriteDecision`**

In `internal/audit/clickhouse.go`, change the `WriteDecision` INSERT to include the new columns:

```go
func (c *clickhouseWriter) WriteDecision(ctx context.Context, d Decision) error {
	return c.conn.Exec(ctx, `
INSERT INTO gate_decisions
(ts, push_id, image_repo, image_tag, image_digest, identity, passed, failed_policies, reasons, base_image_id, trivy_db_version, duration_ms, image_created, image_age_days, image_age_threshold_days)
VALUES (now64(3), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.PushID, d.Repo, d.Tag, d.Digest, d.Identity, d.Passed,
		d.FailedPolicies, d.Reasons, d.BaseImageID, d.TrivyDBVersion, d.DurationMS,
		d.ImageCreated, d.ImageAgeDays, d.ImageAgeThresholdDays)
}
```

- [ ] **Step 4: Add age to `DecisionHeader`**

In `internal/audit/dashboard_reader.go`, extend `DecisionHeader`:

```go
	ImageCreated          time.Time
	ImageAgeDays          uint16
	ImageAgeThresholdDays uint16
```

- [ ] **Step 5: Read age in header queries**

In `internal/audit/dashboard_queries.go`, add the three columns to BOTH the `DecisionHeaderByPush` and `DecisionHeaderByRef` SELECT lists (they share `scanHeader`). Each query currently selects:

```
... base_image_id, trivy_db_version, ts
```

Change both to:

```
... base_image_id, trivy_db_version, ts, image_created, image_age_days, image_age_threshold_days
```

Then extend `scanHeader`'s `row.Scan(...)` to append the three destinations in the same order:

```go
	err := row.Scan(&h.PushID, &h.Repo, &h.Tag, &h.Digest, &h.Identity, &h.Passed,
		&h.FailedPolicies, &h.Reasons, &h.BaseImageID, &h.TrivyDBVersion, &h.Ts,
		&h.ImageCreated, &h.ImageAgeDays, &h.ImageAgeThresholdDays)
```

(Preserve the existing no-rows handling that returns `DecisionHeader{Found: false}`.)

- [ ] **Step 6: Round-trip integration test**

In `internal/audit/clickhouse_integration_test.go`, follow the existing integration-test guard (these tests are build-tagged / skip without a live ClickHouse — match the file's existing pattern exactly). Add a test that writes a decision with age set and reads the header back:

```go
func TestDecisionAgeRoundTrip(t *testing.T) {
	// (use the same setup/skip guard the other tests in this file use)
	w, r, cleanup := newTestClickHouse(t) // existing helper
	defer cleanup()

	created := time.Date(2026, 4, 20, 10, 31, 0, 0, time.UTC)
	d := Decision{
		PushID: newUUID(t), Repo: "app", Tag: "v1", Digest: "sha256:abc",
		Identity: "sp", Passed: false, FailedPolicies: []string{"imageage"},
		Reasons:               []string{"rejected: image age 74d exceeds max 60d"},
		ImageCreated:          created,
		ImageAgeDays:          74,
		ImageAgeThresholdDays: 60,
	}
	if err := w.WriteDecision(context.Background(), d); err != nil {
		t.Fatalf("WriteDecision: %v", err)
	}
	hdr, err := r.DecisionHeaderByPush(context.Background(), d.PushID)
	if err != nil {
		t.Fatalf("DecisionHeaderByPush: %v", err)
	}
	if !hdr.ImageCreated.Equal(created) || hdr.ImageAgeDays != 74 || hdr.ImageAgeThresholdDays != 60 {
		t.Fatalf("age not round-tripped: created=%v days=%d threshold=%d", hdr.ImageCreated, hdr.ImageAgeDays, hdr.ImageAgeThresholdDays)
	}
}
```

Match `newTestClickHouse`/`newUUID` to whatever the file already defines; do not invent new fixtures if equivalents exist.

- [ ] **Step 7: Verify build + unit tests (integration test skips without ClickHouse)**

Run: `go build ./... && go test ./internal/audit/ -race`
Expected: build OK; unit tests PASS; the ClickHouse integration test SKIPS (no live DB) — that is expected in this environment.

- [ ] **Step 8: Commit**

```bash
gofmt -w internal/audit/
git add internal/audit/
git commit -m "feat(audit): persist and read back image age on gate decisions"
```

---

### Task 6: Map age from Result into the audit Decision

**Files:**
- Modify: `internal/ingress/docker/outcome.go` (`recordDecision` maps `Result.Age`)
- Modify: `internal/ingress/docker/outcome_test.go` (age recorded)

**Interfaces:**
- Consumes: `policy.Result.Age`, `audit.Decision` age fields.

- [ ] **Step 1: Write the failing test**

In `internal/ingress/docker/outcome_test.go`, use the existing recorder spy pattern (the tests already capture `audit.Decision` via a fake `DecisionRecorder`; reuse it). Add:

```go
func TestApplyRecordsImageAge(t *testing.T) {
	spy := &recorderSpy{} // existing fake capturing the last Decision + findings
	o := &Outcome{ReportBaseURL: "/reports", Recorder: spy, IDGen: func() string { return "pid" }}

	created := time.Date(2026, 4, 20, 10, 31, 0, 0, time.UTC)
	res := policy.Result{
		Passed: false,
		Verdicts: map[string]policy.Verdict{
			"imageage": {Passed: false, Reasons: []string{"rejected: image age 74d exceeds max 60d"}},
		},
		Age: &policy.AgeInfo{Known: true, Created: created, AgeDays: 74, ThresholdDays: 60, Compliant: false},
	}
	req := router.GateRequest{Image: policy.StagedImage{Repo: "app", Tag: "v1"}, Identity: "sp"}

	_, _ = o.Apply(context.Background(), stubPusher{}, req, res, nil)

	got := spy.lastDecision
	if !got.ImageCreated.Equal(created) || got.ImageAgeDays != 74 || got.ImageAgeThresholdDays != 60 {
		t.Fatalf("age not recorded: %+v", got)
	}
}
```

Reuse the existing `recorderSpy`/`stubPusher` helpers in the docker test package; if their names differ, use the actual ones (grep the test files) rather than redeclaring.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/ingress/docker/ -run TestApplyRecordsImageAge -v`
Expected: FAIL — age fields are zero on the recorded decision.

- [ ] **Step 3: Map `Result.Age` in `recordDecision`**

In `internal/ingress/docker/outcome.go`, inside `recordDecision`, after building the `decision := audit.Decision{...}` literal, add:

```go
	if res.Age != nil && res.Age.Known {
		decision.ImageCreated = res.Age.Created
		decision.ImageAgeDays = clampUint16(res.Age.AgeDays)
		decision.ImageAgeThresholdDays = clampUint16(res.Age.ThresholdDays)
	}
```

Add the helper at the bottom of `outcome.go`:

```go
// clampUint16 converts a non-negative day count to uint16, saturating at the max
// (an age past ~179 years is not a meaningful distinction for the audit row).
func clampUint16(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 65535 {
		return 65535
	}
	return uint16(n)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/ingress/docker/ -run TestApplyRecordsImageAge -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/ingress/docker/outcome.go internal/ingress/docker/outcome_test.go
git add internal/ingress/docker/outcome.go internal/ingress/docker/outcome_test.go
git commit -m "feat(ingress): record image-age result to audit decision"
```

---

### Task 7: Wire the policy, set tenant prefix, add response header, register in app

**Files:**
- Modify: `internal/ingress/docker/manifest.go` (set `req.Image.Prefix`; emit `X-Merlin-Image-Age-Days`)
- Modify: `internal/app/app.go` (build the age policy from config; register in both `Build` and `BuildWithBackends`)
- Modify: `internal/ingress/docker/http_push_integration_test.go` (old image → 400 age reason; fresh → 201 + header)

**Interfaces:**
- Consumes: `imageage.New`, `imageage.Rule`, `config.ImageAgeConfig`, `policy.Result.Age`, `policy.StagedImage.Prefix`.

- [ ] **Step 1: Set the tenant prefix on the gate request**

In `internal/ingress/docker/manifest.go`, where the `router.GateRequest` is built (currently around line 193), set the prefix so the age policy can select the per-tenant rule. Change the `img` population to include the prefix before constructing `req`:

```go
	img.Prefix = t.Prefix
	target := targetRef(t.Registry, repo, ref)
	req := router.GateRequest{
		Source:   "docker",
		Identity: identity.Subject,
		Image:    img,
		Target:   target,
	}
```

(`img` is the value returned by `h.store.Assemble`; it is addressable, so setting the field is fine. If it is not a local variable in scope, assign `img.Prefix = t.Prefix` immediately after the `Assemble` call.)

- [ ] **Step 2: Emit the age header on the manifest response**

In `internal/ingress/docker/manifest.go`, after the block that sets `X-Merlin-Scan-Report-URL` (around line 233) and before `w.WriteHeader(code)`, add:

```go
	// Surface image age to raw-HTTP clients (CI) without a second call. Omitted
	// when age is unknown/disabled (absent header == age not determined).
	if res.Age != nil && res.Age.Known {
		w.Header().Set("X-Merlin-Image-Age-Days", strconv.Itoa(res.Age.AgeDays))
	}
```

Add `"strconv"` to the `manifest.go` imports.

- [ ] **Step 3: Add an app helper that builds age rules from config**

In `internal/app/app.go`, add a helper near the bottom:

```go
// imageAgeRules derives the default age rule and the per-tenant overrides from
// config. A nil per-tenant ImageAge inherits the deployment default.
func imageAgeRules(cfg config.Config) (imageage.Rule, map[string]imageage.Rule) {
	def := imageage.Rule{
		Enabled:       cfg.ImageAge.Enabled == nil || *cfg.ImageAge.Enabled,
		ThresholdDays: cfg.ImageAge.ThresholdDays,
	}
	per := make(map[string]imageage.Rule, len(cfg.Tenants))
	for _, tc := range cfg.Tenants {
		if tc.ImageAge == nil {
			continue
		}
		r := def // start from the default, override present fields
		if tc.ImageAge.Enabled != nil {
			r.Enabled = *tc.ImageAge.Enabled
		}
		if tc.ImageAge.ThresholdDays != 0 {
			r.ThresholdDays = tc.ImageAge.ThresholdDays
		}
		per[tc.Prefix] = r
	}
	return def, per
}
```

Add the import `"github.com/merlin-gate/merlin/internal/policies/imageage"` to `app.go`.

- [ ] **Step 4: Register the age policy in both builders**

In `internal/app/app.go`, in **`Build`** change the engine construction (currently lines 49–51) to:

```go
	trivyPolicy := trivy.New(trivy.NewExecRunner("trivy"), cfg.Trivy.SeverityThreshold)
	basePolicy := baseimage.New(cfg.BaseImage.AllowedIDs)
	def, per := imageAgeRules(cfg)
	agePolicy := imageage.New(def, per)
	engine := policy.NewEngine(trivyPolicy, basePolicy, agePolicy)
```

In **`BuildWithBackends`** change the engine construction (currently lines 222–224) identically:

```go
	trivyPolicy := trivy.New(trivy.NewExecRunner("trivy"), cfg.Trivy.SeverityThreshold)
	basePolicy := baseimage.New(cfg.BaseImage.AllowedIDs)
	def, per := imageAgeRules(cfg)
	agePolicy := imageage.New(def, per)
	engine := policy.NewEngine(trivyPolicy, basePolicy, agePolicy)
```

- [ ] **Step 5: Write the failing integration test**

In `internal/ingress/docker/http_push_integration_test.go`, follow the existing end-to-end push harness in that file (it already stages blobs and drives a manifest PUT through a real `Handler` with fake backends). Add two cases; reuse the harness's image-builder helper and inject a config `created` value. The engine used by the harness must include an `imageage` policy — construct it in the test with a fixed threshold (e.g. `imageage.New(imageage.Rule{Enabled: true, ThresholdDays: 60}, nil)`), matching how the harness builds its engine.

```go
func TestPushRejectsOldImage(t *testing.T) {
	h := newPushHarness(t) // existing helper; ensure its engine includes the age policy
	created := time.Now().Add(-100 * 24 * time.Hour).UTC()
	resp := h.push(t, "app", "v1", withConfigCreated(created)) // helper sets config.created
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "image age") || !strings.Contains(body, "exceeds max") {
		t.Fatalf("expected age reject reason, got %q", body)
	}
}

func TestPushFreshImageSetsAgeHeader(t *testing.T) {
	h := newPushHarness(t)
	created := time.Now().Add(-5 * 24 * time.Hour).UTC()
	resp := h.push(t, "app", "v1", withConfigCreated(created))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Merlin-Image-Age-Days"); got != "5" {
		t.Fatalf("age header = %q, want \"5\"", got)
	}
}
```

If the harness has no per-test config-`created` hook, add `withConfigCreated` as an option on the harness's image builder (it constructs the config JSON — inject the `created` field there). Keep the change confined to the test harness.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/ingress/docker/ -run 'TestPushRejectsOldImage|TestPushFreshImageSetsAgeHeader' -race -v`
Expected: PASS. Then `go build ./...` to confirm both app builders compile.

- [ ] **Step 7: Confirm multi-arch is covered by existing per-child gating (no new code)**

Acceptance criterion §5.4 ("multi-arch index uses the oldest gated child manifest's `created`") requires no dedicated code: Merlin forwards the image *index* verbatim (`handleManifest` → `forwardManifest` for `kindIndex`) and gates each child *image* manifest independently as it is PUT. Each child is age-checked against its own config `created`; the oldest child is therefore the one whose PUT is rejected, and the index only commits once all children are in ACR (see `manifest.go` classify/forward logic and `docs/specs/2026-07-03-merlin-service-spec.md` §7). Verify by reading `handleManifest`: confirm the age policy runs on the per-child image path (the `kind == kindImage` branch that calls `Assemble` + gate), not on the index/attestation forward path. No test is added here beyond Task 3's per-image coverage; note this reasoning in the commit body.

- [ ] **Step 8: Commit**

```bash
gofmt -w internal/ingress/docker/manifest.go internal/app/app.go internal/ingress/docker/http_push_integration_test.go
git add internal/ingress/docker/manifest.go internal/app/app.go internal/ingress/docker/http_push_integration_test.go
git commit -m "feat(gate): register image-age policy, set tenant prefix, emit age header

Multi-arch (spec 5.4) needs no dedicated code: each child image manifest is
gated independently, so the oldest child is the one whose PUT is rejected; the
index forwards verbatim and only commits once all children pass."
```

---

### Task 8: Report envelope carries the age result

**Files:**
- Modify: `internal/ingress/docker/report.go` (return `{age, findings}` envelope; fetch age)
- Modify: `internal/audit/dashboard_reader.go` OR a new small type — expose age lookups on the report source (see Step 1)
- Modify: `internal/audit/clickhouse.go` (implement the age lookups)
- Modify: `internal/ingress/docker/report_test.go`

**Interfaces:**
- Produces: `docker.ReportAge{Known bool; Created time.Time; AgeDays int; ThresholdDays int; Compliant bool}` (JSON-friendly view for the envelope).
- Produces: envelope `{"age": ReportAge|null, "findings": []policy.Finding}` at `GET /reports/<ref>`.
- Extends: `docker.ReportSource` with `AgeByPush` / `AgeByImageRef`, returning `audit.DecisionHeader` (age fields), reusing the existing `DecisionHeaderByPush`/`DecisionHeaderByRef` reader methods.

- [ ] **Step 1: Extend `ReportSource` with header (age) lookups**

In `internal/ingress/docker/report.go`, extend the `ReportSource` interface so the handler can read the decision header (which now carries age):

```go
type ReportSource interface {
	FindingsByPush(ctx context.Context, pushID string) ([]policy.Finding, error)
	FindingsByImageRef(ctx context.Context, repo, ref string) ([]policy.Finding, error)
	HeaderByPush(ctx context.Context, pushID string) (audit.DecisionHeader, error)
	HeaderByImageRef(ctx context.Context, repo, ref string) (audit.DecisionHeader, error)
}
```

Add the `audit` import to `report.go`. The ClickHouse `*audit.Reader` already implements `DecisionHeaderByPush`/`DecisionHeaderByRef`; add thin adapter methods so it satisfies the new names (in `internal/audit/clickhouse.go` or `dashboard_queries.go`):

```go
// HeaderByPush and HeaderByImageRef alias the DecisionHeader lookups under the
// names the report ingress depends on.
func (r *Reader) HeaderByPush(ctx context.Context, pushID string) (DecisionHeader, error) {
	return r.DecisionHeaderByPush(ctx, pushID)
}
func (r *Reader) HeaderByImageRef(ctx context.Context, repo, ref string) (DecisionHeader, error) {
	return r.DecisionHeaderByRef(ctx, repo, ref)
}
```

- [ ] **Step 2: Build the envelope in `handleReport`**

In `internal/ingress/docker/report.go`, define the JSON view and change the handler to emit the envelope. Replace the findings-only encoding at the end of `handleReport`:

```go
// ReportAge is the JSON view of the image-age result in a scan report.
type ReportAge struct {
	Known         bool      `json:"known"`
	Created       time.Time `json:"created"`
	AgeDays       int       `json:"age_days"`
	ThresholdDays int       `json:"threshold_days"`
	Compliant     bool      `json:"compliant"`
}

// reportEnvelope is the GET /reports/<ref> body: the age result (null when the
// age policy was disabled / age unknown) plus the Trivy findings.
type reportEnvelope struct {
	Age      *ReportAge       `json:"age"`
	Findings []policy.Finding `json:"findings"`
}
```

In the handler, after resolving `repo/ref` vs `push_id`, fetch BOTH findings and the header, then build the envelope:

```go
	var (
		findings []policy.Finding
		hdr      audit.DecisionHeader
	)
	if repo, ref, ok := splitImageRef(id); ok {
		findings, err = h.reports.FindingsByImageRef(r.Context(), repo, ref)
		if err == nil {
			hdr, _ = h.reports.HeaderByImageRef(r.Context(), repo, ref)
		}
	} else {
		findings, err = h.reports.FindingsByPush(r.Context(), id)
		if err == nil {
			hdr, _ = h.reports.HeaderByPush(r.Context(), id)
		}
	}
	if err != nil {
		http.Error(w, "report unavailable", http.StatusInternalServerError)
		return
	}

	env := reportEnvelope{Findings: findings}
	if hdr.Found && !hdr.ImageCreated.IsZero() {
		env.Age = &ReportAge{
			Known:         true,
			Created:       hdr.ImageCreated,
			AgeDays:       int(hdr.ImageAgeDays),
			ThresholdDays: int(hdr.ImageAgeThresholdDays),
			Compliant:     int(hdr.ImageAgeDays) <= int(hdr.ImageAgeThresholdDays),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
```

Add `"time"` to the `report.go` imports.

- [ ] **Step 3: Update the report test for the envelope**

In `internal/ingress/docker/report_test.go`, the existing fake `ReportSource` must gain the two header methods. Update the fake and the assertions to expect the envelope. Add a case with age set:

```go
func TestReportEnvelopeIncludesAge(t *testing.T) {
	created := time.Date(2026, 4, 20, 10, 31, 0, 0, time.UTC)
	src := &fakeReports{
		findings: []policy.Finding{{CVE: "CVE-1", Severity: "HIGH"}},
		header: audit.DecisionHeader{
			Found: true, ImageCreated: created, ImageAgeDays: 74, ImageAgeThresholdDays: 60,
		},
	}
	// ... drive GET /reports/app:v1 through the handler (reuse existing test rig) ...
	var env reportEnvelope
	if err := json.Unmarshal(bodyBytes, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.Age == nil || env.Age.AgeDays != 74 || env.Age.Compliant {
		t.Fatalf("age missing/wrong in envelope: %+v", env.Age)
	}
	if len(env.Findings) != 1 || env.Findings[0].CVE != "CVE-1" {
		t.Fatalf("findings missing from envelope: %+v", env.Findings)
	}
}
```

Extend the existing `fakeReports` (or whatever the file names its fake) with a `header audit.DecisionHeader` field and the `HeaderByPush`/`HeaderByImageRef` methods returning it. Update any existing report test that decoded a bare array to decode `reportEnvelope` and read `.Findings`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/ingress/docker/ -run TestReport -race -v && go build ./...`
Expected: PASS; build OK.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/ingress/docker/report.go internal/audit/clickhouse.go internal/ingress/docker/report_test.go
git add internal/ingress/docker/report.go internal/audit/clickhouse.go internal/ingress/docker/report_test.go
git commit -m "feat(reports): return {age, findings} envelope from /reports/<ref>"
```

---

### Task 9: Dashboard rendering + documentation

**Files:**
- Modify: `internal/dashboard/data.go` (age fields on `ReportVM` / `ImageVM`)
- Modify: `internal/audit/dashboard_reader.go` (`ImageRow` age; if the images table should show age)
- Modify: `internal/dashboard/data_test.go`
- Modify: dashboard template(s) under `internal/dashboard/` (render age in the report view)
- Modify: `docs/USAGE.md`, `docs/CI.md` (image-age note + report envelope)

**Interfaces:**
- Consumes: `audit.DecisionHeader` age fields (already populated in Task 5).

- [ ] **Step 1: Add age to the report view model**

In `internal/dashboard/data.go`, in `Report()` where `ReportVM` is populated from `hdr` (around line 84–87), add age fields. First extend `ReportVM` (find its definition in the dashboard package) with:

```go
	ImageCreated  time.Time
	ImageAgeDays  int
	ImageAgeKnown bool
	AgeThreshold  int
	AgeCompliant  bool
```

Then populate them in `Report()`:

```go
	vm.ImageAgeKnown = !hdr.ImageCreated.IsZero()
	if vm.ImageAgeKnown {
		vm.ImageCreated = hdr.ImageCreated
		vm.ImageAgeDays = int(hdr.ImageAgeDays)
		vm.AgeThreshold = int(hdr.ImageAgeThresholdDays)
		vm.AgeCompliant = int(hdr.ImageAgeDays) <= int(hdr.ImageAgeThresholdDays)
	}
```

- [ ] **Step 2: Render age in the report template**

Locate the report template in `internal/dashboard/` (grep for `TrivyDBVersion` or `BaseImageID` in `*.html`/`*.tmpl` — the report page renders those). Add an age line near the provenance block:

```html
{{if .ImageAgeKnown}}
  <div class="report-age {{if .AgeCompliant}}ok{{else}}bad{{end}}">
    Image age: {{.ImageAgeDays}}d (threshold {{.AgeThreshold}}d) —
    created {{.ImageCreated.Format "2006-01-02 15:04"}}
  </div>
{{else}}
  <div class="report-age unknown">Image age: unknown</div>
{{end}}
```

Match the surrounding template's class/markup conventions (inspect adjacent blocks); the exact styling is not load-bearing, but the `ImageAgeKnown` guard is.

- [ ] **Step 3: Update the dashboard data test**

In `internal/dashboard/data_test.go`, extend the existing `Report()` test's fake header with age fields and assert the VM carries them:

```go
	// in the fake DashboardReader's DecisionHeaderByRef/ByPush return value:
	ImageCreated: time.Date(2026, 4, 20, 10, 31, 0, 0, time.UTC),
	ImageAgeDays: 74, ImageAgeThresholdDays: 60,
	// assertions:
	if !vm.ImageAgeKnown || vm.ImageAgeDays != 74 || vm.AgeCompliant {
		t.Fatalf("age VM wrong: known=%v days=%d compliant=%v", vm.ImageAgeKnown, vm.ImageAgeDays, vm.AgeCompliant)
	}
```

Reuse the file's existing fake reader; only add the age fields to what it returns.

- [ ] **Step 4: Run dashboard tests + full build**

Run: `go test ./internal/dashboard/ -race && go build ./...`
Expected: PASS; build OK. If a template parses at startup, also run any existing renderer test to confirm the template still parses.

- [ ] **Step 5: Update the docs**

In `docs/USAGE.md`, add a section after "Get the Trivy scan results":

```markdown
## Image age

Merlin also gates on **image age**. It reads the image config's `created`
timestamp and rejects any image older than the configured threshold (default
**60 days**, configurable per tenant). A too-old image fails the push with, e.g.:

    rejected: image age 74d exceeds max 60d (created 2026-04-20T10:31:00Z)

An image whose `created` cannot be read is rejected (fail-closed) with a distinct
"could not determine image age" reason.

The manifest PUT response carries `X-Merlin-Image-Age-Days`, and the scan report
includes an `age` object:

    { "age": { "known": true, "created": "...", "age_days": 45,
               "threshold_days": 60, "compliant": true },
      "findings": [ ... ] }
```

In `docs/CI.md`: (a) add image-age to the gate-blocking list in "Interpreting the outcome"; (b) update the "Pulling the scan report" section — the report body is now the `{age, findings}` envelope, so the `jq` example changes from `.[]` to `.findings[]`, and note `.age`.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/dashboard/data.go internal/dashboard/data_test.go internal/audit/dashboard_reader.go
git add internal/dashboard/ internal/audit/dashboard_reader.go docs/USAGE.md docs/CI.md
git commit -m "feat(dashboard): show image age in report; docs for image-age gate"
```

---

## Final verification

- [ ] Run the full suite: `go build ./... && go test -race ./internal/...`
  Expected: all PASS; ClickHouse integration tests SKIP without a live DB.
- [ ] `gofmt -l internal/ | grep . && echo "UNFORMATTED" || echo "clean"` → `clean`.
- [ ] Manual spec cross-check against `docs/specs/2026-07-03-merlin-image-age-compliance-spec.md` acceptance criteria §5 (all six covered by Tasks 1–9).
