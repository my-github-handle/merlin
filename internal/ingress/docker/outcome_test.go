package docker

import (
	"context"
	"errors"
	"testing"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
)

func TestOutcomePassPushesAndReturns201(t *testing.T) {
	fp := &acr.FakePusher{}
	o := &Outcome{Pusher: fp, ReportBaseURL: "https://merlin/reports"}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci", Digest: "sha256:abc"}}
	d, err := o.Apply(context.Background(), req, policy.Result{Passed: true}, nil)
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
	o := &Outcome{Pusher: fp, ReportBaseURL: "https://merlin/reports"}
	req := router.GateRequest{Target: "t", Image: policy.StagedImage{Digest: "sha256:abc"}}
	res := policy.Result{Passed: false, Findings: []policy.Finding{{CVE: "CVE-1", Severity: "CRITICAL", Pkg: "p"}}}
	d, _ := o.Apply(context.Background(), req, res, nil)
	if len(fp.Pushed) != 0 {
		t.Error("must not push on fail")
	}
	if d.StatusCode != 400 {
		t.Errorf("status = %d, want 400", d.StatusCode)
	}
}

func TestOutcomeInfraErrorIs500(t *testing.T) {
	fp := &acr.FakePusher{}
	o := &Outcome{Pusher: fp}
	req := router.GateRequest{Image: policy.StagedImage{Digest: "sha256:abc"}}
	d, _ := o.Apply(context.Background(), req, policy.Result{}, context.DeadlineExceeded)
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
		Pusher:        fp,
		ReportBaseURL: "https://merlin/reports",
		Recorder:      spy,
		IDGen:         func() string { return "push-xyz" },
	}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci"}}
	d, err := o.Apply(context.Background(), req, policy.Result{Passed: true}, nil)
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
	o := &Outcome{Pusher: fp, ReportBaseURL: "https://merlin/reports"}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci", Digest: "sha256:abc"}}
	d, err := o.Apply(context.Background(), req, policy.Result{Passed: true}, nil)
	if err == nil {
		t.Error("expected error when ACR push fails")
	}
	if d.StatusCode != 502 || !d.InfraError {
		t.Errorf("expected 502 infra after failed push, got %+v", d)
	}
}
