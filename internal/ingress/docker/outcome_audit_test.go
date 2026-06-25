package docker

import (
	"context"
	"errors"
	"testing"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
)

var errFake = errors.New("fake infra error")

// spyRecorder captures calls to Record for test assertions.
type spyRecorder struct {
	calls []recordCall
}

type recordCall struct {
	decision audit.Decision
	findings []policy.Finding
}

func (s *spyRecorder) Record(_ context.Context, d audit.Decision, findings []policy.Finding) {
	s.calls = append(s.calls, recordCall{decision: d, findings: findings})
}

func TestOutcome_RecordsPassDecision(t *testing.T) {
	spy := &spyRecorder{}
	o := Outcome{
		Pusher:        &acr.FakePusher{},
		ReportBaseURL: "http://reports",
		Recorder:      spy,
		IDGen:         func() string { return "test-id-001" },
	}
	req := router.GateRequest{
		Source:   "docker-registry",
		Identity: "user@example.com",
		Image: policy.StagedImage{
			Repo:    "myrepo",
			Tag:     "v1.0.0",
			Digest:  "sha256:abc123",
			FSPath:  "/tmp/img",
			OCIPath: "/tmp/oci",
		},
		Target: "acr.io/myrepo:v1.0.0",
	}
	res := policy.Result{
		Passed: true,
		Verdicts: map[string]policy.Verdict{
			"trivy": {Passed: true, ScannerDBVersion: "db-v1"},
		},
		Findings:       []policy.Finding{{CVE: "CVE-2024-1234", Severity: "LOW"}},
		TrivyDBVersion: "db-v1",
	}

	_, err := o.Apply(context.Background(), req, res, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 Record call, got %d", len(spy.calls))
	}
	call := spy.calls[0]
	if call.decision.PushID != "test-id-001" {
		t.Errorf("PushID = %q, want test-id-001", call.decision.PushID)
	}
	if call.decision.Repo != "myrepo" {
		t.Errorf("Repo = %q, want myrepo", call.decision.Repo)
	}
	if call.decision.Tag != "v1.0.0" {
		t.Errorf("Tag = %q, want v1.0.0", call.decision.Tag)
	}
	if call.decision.Digest != "sha256:abc123" {
		t.Errorf("Digest = %q, want sha256:abc123", call.decision.Digest)
	}
	if call.decision.Identity != "user@example.com" {
		t.Errorf("Identity = %q, want user@example.com", call.decision.Identity)
	}
	if !call.decision.Passed {
		t.Error("Passed = false, want true")
	}
	if len(call.decision.FailedPolicies) != 0 {
		t.Errorf("FailedPolicies = %v, want []", call.decision.FailedPolicies)
	}
	if call.decision.TrivyDBVersion != "db-v1" {
		t.Errorf("TrivyDBVersion = %q, want db-v1", call.decision.TrivyDBVersion)
	}
	if len(call.findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(call.findings))
	}
	if call.findings[0].CVE != "CVE-2024-1234" {
		t.Errorf("findings[0].CVE = %q, want CVE-2024-1234", call.findings[0].CVE)
	}
}

func TestOutcome_RecordsFailDecision(t *testing.T) {
	spy := &spyRecorder{}
	o := Outcome{
		Pusher:        &acr.FakePusher{},
		ReportBaseURL: "http://reports",
		Recorder:      spy,
		IDGen:         func() string { return "test-id-002" },
	}
	req := router.GateRequest{
		Source:   "docker-registry",
		Identity: "user@example.com",
		Image: policy.StagedImage{
			Repo:   "myrepo",
			Tag:    "v1.0.0",
			Digest: "sha256:abc123",
		},
		Target: "acr.io/myrepo:v1.0.0",
	}
	res := policy.Result{
		Passed: false,
		Verdicts: map[string]policy.Verdict{
			"trivy": {Passed: false, Reasons: []string{"critical vuln found"}, ScannerDBVersion: "db-v1"},
			"base":  {Passed: false, Reasons: []string{"base image rejected"}},
		},
		Findings:       []policy.Finding{{CVE: "CVE-2024-9999", Severity: "CRITICAL"}},
		TrivyDBVersion: "db-v1",
	}

	_, err := o.Apply(context.Background(), req, res, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 Record call, got %d", len(spy.calls))
	}
	call := spy.calls[0]
	if call.decision.Passed {
		t.Error("Passed = true, want false")
	}
	if len(call.decision.FailedPolicies) != 2 {
		t.Errorf("FailedPolicies count = %d, want 2", len(call.decision.FailedPolicies))
	}
	// FailedPolicies order may vary (from map), just check they're present
	hasTrivyFail := false
	hasBaseFail := false
	for _, p := range call.decision.FailedPolicies {
		if p == "trivy" {
			hasTrivyFail = true
		}
		if p == "base" {
			hasBaseFail = true
		}
	}
	if !hasTrivyFail || !hasBaseFail {
		t.Errorf("FailedPolicies = %v, want [trivy, base]", call.decision.FailedPolicies)
	}
	if len(call.decision.Reasons) != 2 {
		t.Errorf("Reasons count = %d, want 2", len(call.decision.Reasons))
	}
	if len(call.findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(call.findings))
	}
	if call.findings[0].CVE != "CVE-2024-9999" {
		t.Errorf("findings[0].CVE = %q, want CVE-2024-9999", call.findings[0].CVE)
	}
}

func TestOutcome_RecordsInfraErrorDecision(t *testing.T) {
	spy := &spyRecorder{}
	o := Outcome{
		Pusher:        &acr.FakePusher{},
		ReportBaseURL: "http://reports",
		Recorder:      spy,
		IDGen:         func() string { return "test-id-003" },
	}
	req := router.GateRequest{
		Identity: "user@example.com",
		Image: policy.StagedImage{
			Repo:   "myrepo",
			Tag:    "v1.0.0",
			Digest: "sha256:abc123",
		},
	}
	res := policy.Result{Passed: false}

	_, err := o.Apply(context.Background(), req, res, errFake)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 Record call on infra error, got %d", len(spy.calls))
	}
	call := spy.calls[0]
	if call.decision.Passed {
		t.Error("Passed = true on infra error, want false")
	}
}

func TestOutcome_NilRecorderDoesNotPanic(t *testing.T) {
	o := Outcome{
		Pusher:        &acr.FakePusher{},
		ReportBaseURL: "http://reports",
		Recorder:      nil, // no recorder
		IDGen:         func() string { return "test-id-004" },
	}
	req := router.GateRequest{
		Identity: "user@example.com",
		Image: policy.StagedImage{
			Repo:   "myrepo",
			Tag:    "v1.0.0",
			Digest: "sha256:def456",
		},
	}
	res := policy.Result{Passed: true}

	_, err := o.Apply(context.Background(), req, res, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	// No panic = pass
}
