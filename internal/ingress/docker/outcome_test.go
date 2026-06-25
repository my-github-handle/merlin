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
