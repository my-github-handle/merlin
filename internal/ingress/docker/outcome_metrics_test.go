package docker

import (
	"context"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
)

// spyMetrics captures MetricsObserver calls for assertions.
type spyMetrics struct {
	pushes       []bool    // ObservePush(passed)
	acrPushes    []bool    // ObserveACRPush(ok)
	scanSecs     []float64 // ObserveScanDuration(seconds)
	assembleSecs []float64 // ObserveAssembleDuration(seconds)
	queueSecs    []float64 // ObserveQueueWait(seconds)
	promoteSecs  []float64 // ObservePromoteDuration(seconds)
}

func (s *spyMetrics) ObservePush(passed bool)         { s.pushes = append(s.pushes, passed) }
func (s *spyMetrics) ObserveACRPush(ok bool)          { s.acrPushes = append(s.acrPushes, ok) }
func (s *spyMetrics) ObserveScanDuration(sec float64) { s.scanSecs = append(s.scanSecs, sec) }

// The three below are NOT part of MetricsObserver: producers reach them through
// an optional interface assertion (Outcome.observePromote, Handler.observeQueueWait),
// so fakes that omit them keep compiling. This one implements them to assert the
// non-scan phases of the blocked window are observed.
func (s *spyMetrics) ObserveAssembleDuration(sec float64) {
	s.assembleSecs = append(s.assembleSecs, sec)
}
func (s *spyMetrics) ObserveQueueWait(sec float64) { s.queueSecs = append(s.queueSecs, sec) }
func (s *spyMetrics) ObservePromoteDuration(sec float64) {
	s.promoteSecs = append(s.promoteSecs, sec)
}

func TestOutcome_ObservesPassPushAndACR(t *testing.T) {
	sm := &spyMetrics{}
	fp := &acr.FakePusher{}
	o := &Outcome{ReportBaseURL: "https://merlin/reports", Metrics: sm}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci"}}

	if _, err := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{Passed: true}, nil, 0); err != nil {
		t.Fatal(err)
	}

	if len(sm.pushes) != 1 || sm.pushes[0] != true {
		t.Errorf("ObservePush = %v, want [true]", sm.pushes)
	}
	if len(sm.acrPushes) != 1 || sm.acrPushes[0] != true {
		t.Errorf("ObserveACRPush = %v, want [true]", sm.acrPushes)
	}
}

func TestOutcome_ObservesRejectNoACRPush(t *testing.T) {
	sm := &spyMetrics{}
	fp := &acr.FakePusher{}
	o := &Outcome{ReportBaseURL: "https://merlin/reports", Metrics: sm}
	req := router.GateRequest{Target: "t", Image: policy.StagedImage{}}

	if _, err := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{Passed: false}, nil, 0); err != nil {
		t.Fatal(err)
	}

	if len(sm.pushes) != 1 || sm.pushes[0] != false {
		t.Errorf("ObservePush = %v, want [false]", sm.pushes)
	}
	// A rejected image is never pushed to ACR, so no ACR push is observed.
	if len(sm.acrPushes) != 0 {
		t.Errorf("ObserveACRPush = %v, want none on reject", sm.acrPushes)
	}
}

func TestOutcome_ObservesACRPushFailure(t *testing.T) {
	sm := &spyMetrics{}
	fp := &acr.FakePusher{Err: errFake} // passing gate, but ACR push fails
	o := &Outcome{ReportBaseURL: "https://merlin/reports", Metrics: sm}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci"}}

	if _, err := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{Passed: true}, nil, 0); err == nil {
		t.Fatal("expected ACR push error")
	}

	if len(sm.acrPushes) != 1 || sm.acrPushes[0] != false {
		t.Errorf("ObserveACRPush = %v, want [false] on push failure", sm.acrPushes)
	}
}

func TestOutcome_RecordsScanDurationInAuditAndMetric(t *testing.T) {
	sm := &spyMetrics{}
	spy := &spyRecorder{}
	fp := &acr.FakePusher{}
	o := &Outcome{ReportBaseURL: "https://merlin/reports", Recorder: spy, Metrics: sm}
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci"}}

	if _, err := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{Passed: true}, nil, 250*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 recorded decision, got %d", len(spy.calls))
	}
	if got := spy.calls[0].decision.DurationMS; got != 250 {
		t.Errorf("DurationMS = %d, want 250", got)
	}
	if len(sm.scanSecs) != 1 || sm.scanSecs[0] != 0.25 {
		t.Errorf("ObserveScanDuration = %v, want [0.25]", sm.scanSecs)
	}
}

// TestOutcome_InfraErrorObservesDurationNotPush pins the deliberate semantic: a
// gate infra error (500) is NOT a pass/reject decision, so it must not inflate
// merlin_push_decisions_total — but the scan was still attempted, so its duration
// is observed.
func TestOutcome_InfraErrorObservesDurationNotPush(t *testing.T) {
	sm := &spyMetrics{}
	o := &Outcome{ReportBaseURL: "https://merlin/reports", Metrics: sm}
	req := router.GateRequest{Target: "t", Image: policy.StagedImage{}}

	if _, err := o.Apply(context.Background(), "", SyncPublish(&acr.FakePusher{}, req), req, policy.Result{}, errFake, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	if len(sm.pushes) != 0 {
		t.Errorf("ObservePush = %v, want none on infra error", sm.pushes)
	}
	if len(sm.acrPushes) != 0 {
		t.Errorf("ObserveACRPush = %v, want none on infra error", sm.acrPushes)
	}
	if len(sm.scanSecs) != 1 || sm.scanSecs[0] != 0.1 {
		t.Errorf("ObserveScanDuration = %v, want [0.1]", sm.scanSecs)
	}
}

func TestOutcome_NilMetricsIsSafe(t *testing.T) {
	fp := &acr.FakePusher{}
	o := &Outcome{ReportBaseURL: "https://merlin/reports"} // Metrics nil
	req := router.GateRequest{Target: "myreg.azurecr.io/app:v1", Image: policy.StagedImage{OCIPath: "/oci"}}
	if _, err := o.Apply(context.Background(), "", SyncPublish(fp, req), req, policy.Result{Passed: true}, nil, 0); err != nil {
		t.Fatalf("nil Metrics must be safe: %v", err)
	}
}
