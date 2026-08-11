package docker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
)

func TestOutcomePassPushesAndReturns201(t *testing.T) {
	fp := &acr.FakePusher{}
	o := &Outcome{ReportBaseURL: "https://merlin/reports"}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci", Digest: "sha256:abc"}}
	d, err := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{Passed: true}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp.Pushed) != 1 {
		t.Errorf("expected push, got %v", fp.Pushed)
	}
	if d.StatusCode != 201 {
		t.Errorf("status = %d, want 201", d.StatusCode)
	}
}

func TestOutcomeFailDoesNotPush(t *testing.T) {
	fp := &acr.FakePusher{}
	o := &Outcome{ReportBaseURL: "https://merlin/reports"}
	req := router.GateRequest{Target: "t", Image: policy.StagedImage{Digest: "sha256:abc"}}
	res := policy.Result{Passed: false, Findings: []policy.Finding{{CVE: "CVE-1", Severity: "CRITICAL", Pkg: "p"}}}
	d, _ := o.Apply(context.Background(), "", SyncPublish(fp, req), req, res, nil, 0)
	if len(fp.Pushed) != 0 {
		t.Error("must not push on fail")
	}
	if d.StatusCode != 400 {
		t.Errorf("status = %d, want 400", d.StatusCode)
	}
}

func TestOutcomeInfraErrorIs500(t *testing.T) {
	fp := &acr.FakePusher{}
	o := &Outcome{}
	req := router.GateRequest{Image: policy.StagedImage{Digest: "sha256:abc"}}
	d, _ := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{}, context.DeadlineExceeded, 0)
	if d.StatusCode != 500 || !d.InfraError {
		t.Errorf("expected 500 infra, got %+v", d)
	}
	if len(fp.Pushed) != 0 {
		t.Error("must not push on infra error")
	}
}

// TestOutcomeReportURLMatchesRecordedPushID verifies the report URL is keyed by
// the SAME push_id recorded in the audit store, so GET /reports/<id> resolves.
// (Previously the URL used the image digest while findings were stored by push_id,
// and the digest was empty — so the report endpoint could never find the scan.)
func TestOutcomeReportURLMatchesRecordedPushID(t *testing.T) {
	fp := &acr.FakePusher{}
	spy := &spyRecorder{}
	o := &Outcome{
		ReportBaseURL: "https://merlin/reports",
		Recorder:      spy,
		IDGen:         func() string { return "push-xyz" },
	}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci"}}
	d, err := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{Passed: true}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://merlin/reports/push-xyz"; d.ReportURL != want {
		t.Errorf("ReportURL = %q, want %q", d.ReportURL, want)
	}
	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 recorded decision, got %d", len(spy.calls))
	}
	recordedID := spy.calls[0].decision.PushID
	if recordedID != "push-xyz" {
		t.Errorf("recorded PushID = %q, want push-xyz", recordedID)
	}
	if d.ReportURL != "https://merlin/reports/"+recordedID {
		t.Errorf("report URL %q must end with recorded push_id %q", d.ReportURL, recordedID)
	}
}

func TestOutcomePushFailureIs502(t *testing.T) {
	fp := &acr.FakePusher{Err: errors.New("acr unreachable")}
	o := &Outcome{ReportBaseURL: "https://merlin/reports"}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci", Digest: "sha256:abc"}}
	d, err := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{Passed: true}, nil, 0)
	if err == nil {
		t.Error("expected error when ACR push fails")
	}
	if d.StatusCode != 502 || !d.InfraError {
		t.Errorf("expected 502 infra after failed push, got %+v", d)
	}
}

func TestApplyRecordsImageAge(t *testing.T) {
	spy := &spyRecorder{}
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

	_, _ = o.Apply(context.Background(), "", SyncPublish(&acr.FakePusher{}, req), req, res, nil, 0)

	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 recorded call, got %d", len(spy.calls))
	}
	got := spy.calls[0].decision
	if !got.ImageCreated.Equal(created) || got.ImageAgeDays != 74 || got.ImageAgeThresholdDays != 60 {
		t.Fatalf("age not recorded: ImageCreated=%v (want %v), ImageAgeDays=%d (want 74), ImageAgeThresholdDays=%d (want 60)",
			got.ImageCreated, created, got.ImageAgeDays, got.ImageAgeThresholdDays)
	}
}
