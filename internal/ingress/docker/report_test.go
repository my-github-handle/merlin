package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
)

type fakeReports struct {
	findings []policy.Finding
	header   audit.DecisionHeader
	// captured args from the last lookup, for assertions
	gotPushID  string
	gotRepo    string
	gotRef     string
	byImageRef bool
}

func (f *fakeReports) FindingsByPush(_ context.Context, pushID string) ([]policy.Finding, error) {
	f.gotPushID = pushID
	return f.findings, nil
}

func (f *fakeReports) FindingsByImageRef(_ context.Context, repo, ref string) ([]policy.Finding, error) {
	f.byImageRef = true
	f.gotRepo, f.gotRef = repo, ref
	return f.findings, nil
}

func (f *fakeReports) HeaderByPush(_ context.Context, pushID string) (audit.DecisionHeader, error) {
	return f.header, nil
}

func (f *fakeReports) HeaderByImageRef(_ context.Context, repo, ref string) (audit.DecisionHeader, error) {
	return f.header, nil
}

type errReports struct{}

func (errReports) FindingsByPush(_ context.Context, _ string) ([]policy.Finding, error) {
	return nil, errors.New("audit store down")
}

func (errReports) FindingsByImageRef(_ context.Context, _, _ string) ([]policy.Finding, error) {
	return nil, errors.New("audit store down")
}

func (errReports) HeaderByPush(_ context.Context, _ string) (audit.DecisionHeader, error) {
	return audit.DecisionHeader{}, errors.New("audit store down")
}

func (errReports) HeaderByImageRef(_ context.Context, _, _ string) (audit.DecisionHeader, error) {
	return audit.DecisionHeader{}, errors.New("audit store down")
}

func TestReportEndpointReturnsFindings(t *testing.T) {
	rs := &fakeReports{findings: []policy.Finding{{CVE: "CVE-1", Severity: "CRITICAL", Pkg: "openssl"}}}
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var env reportEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Findings) != 1 || env.Findings[0].CVE != "CVE-1" {
		t.Errorf("findings = %+v", env.Findings)
	}
}

func TestSplitImageRef(t *testing.T) {
	tests := []struct {
		id       string
		wantRepo string
		wantRef  string
		wantOK   bool
	}{
		{"c3aiops:2.13.25-as", "c3aiops", "2.13.25-as", true},
		{"e2e/app:v1", "e2e/app", "v1", true},
		{"deep/path/app:tag", "deep/path/app", "tag", true},
		{"app@sha256:abc123", "app", "sha256:abc123", true},
		{"e2e/app@sha256:abc123", "e2e/app", "sha256:abc123", true},
		{"88824db0a4604bf48aad9ec246144d20", "", "", false}, // push_id, no ':' or '@'
	}
	for _, tc := range tests {
		repo, ref, ok := splitImageRef(tc.id)
		if ok != tc.wantOK || repo != tc.wantRepo || ref != tc.wantRef {
			t.Errorf("splitImageRef(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.id, repo, ref, ok, tc.wantRepo, tc.wantRef, tc.wantOK)
		}
	}
}

func TestReportEndpointByImageTag(t *testing.T) {
	rs := &fakeReports{findings: []policy.Finding{{CVE: "CVE-X", Severity: "CRITICAL"}}}
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/c3aiops:2.13.25-as", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if !rs.byImageRef || rs.gotRepo != "c3aiops" || rs.gotRef != "2.13.25-as" {
		t.Errorf("expected image-ref lookup repo=c3aiops ref=2.13.25-as, got byRef=%v repo=%q ref=%q",
			rs.byImageRef, rs.gotRepo, rs.gotRef)
	}
}

func TestReportEndpointByImageDigest(t *testing.T) {
	rs := &fakeReports{header: audit.DecisionHeader{Found: true}}
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/e2e/app@sha256:deadbeef", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if !rs.byImageRef || rs.gotRepo != "e2e/app" || rs.gotRef != "sha256:deadbeef" {
		t.Errorf("digest lookup: byRef=%v repo=%q ref=%q", rs.byImageRef, rs.gotRepo, rs.gotRef)
	}
}

func TestReportEndpointByPushIDStillWorks(t *testing.T) {
	rs := &fakeReports{header: audit.DecisionHeader{Found: true}}
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/88824db0a4604bf48aad9ec246144d20", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if rs.byImageRef || rs.gotPushID != "88824db0a4604bf48aad9ec246144d20" {
		t.Errorf("expected push_id lookup, got byRef=%v pushID=%q", rs.byImageRef, rs.gotPushID)
	}
}

func TestReportEndpointRejectsUnauthenticated(t *testing.T) {
	rs := &fakeReports{}
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: false}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Host = testTenantHost
	// no Authorization header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated report request: code = %d, want 401", rec.Code)
	}
}

func TestReportEndpointErrorIs500(t *testing.T) {
	rs := errReports{} // FindingsByPush returns an error
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("report store error: code = %d, want 500", rec.Code)
	}
}

// A recorded decision with zero findings (clean image) is 200 with an empty
// findings array — [] not null, so jq-style consumers can iterate safely.
func TestReportEndpointEmptyFindingsOK(t *testing.T) {
	rs := &fakeReports{findings: nil, header: audit.DecisionHeader{Found: true}}
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("empty findings: code = %d, want 200", rec.Code)
	}
	var env reportEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.Findings == nil {
		t.Error("findings = null, want []")
	}
}

// A reference with no recorded gate decision is 404, NOT an empty 200: "we never
// scanned this" must be distinguishable from "we scanned it and found nothing".
func TestReportEndpointUnknownRefIs404(t *testing.T) {
	rs := &fakeReports{} // header zero value: Found=false, no findings
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/app:never-pushed", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown ref: code = %d, want 404", rec.Code)
	}
}

// An infra-error decision surfaces infra_error + error in the envelope so a CI
// consumer never mistakes "scan did not complete" for "image is clean".
func TestReportEnvelopeCarriesInfraError(t *testing.T) {
	rs := &fakeReports{header: audit.DecisionHeader{
		Found: true, InfraError: true, ErrorDetail: `policy "grype" could not run: run grype: signal: killed`,
	}}
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var env reportEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.InfraError || env.Error == "" {
		t.Errorf("envelope infra_error=%v error=%q, want true + non-empty", env.InfraError, env.Error)
	}
}

func TestReportEnvelopeIncludesAge(t *testing.T) {
	created := time.Date(2026, 4, 20, 10, 31, 0, 0, time.UTC)
	rs := &fakeReports{
		findings: []policy.Finding{{CVE: "CVE-1", Severity: "HIGH"}},
		header: audit.DecisionHeader{
			Found:                 true,
			ImageCreated:          created,
			ImageAgeDays:          74,
			ImageAgeThresholdDays: 60,
			ImageAgeKnown:         true,
		},
	}
	h := NewHandler(testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), nil, nil, nil, rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/app:v1", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var env reportEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.Age == nil {
		t.Fatal("age is nil, expected non-nil")
	}
	if !env.Age.Known || env.Age.AgeDays != 74 || env.Age.ThresholdDays != 60 || env.Age.Compliant {
		t.Fatalf("age wrong: Known=%v AgeDays=%d Threshold=%d Compliant=%v, want Known=true Days=74 Threshold=60 Compliant=false",
			env.Age.Known, env.Age.AgeDays, env.Age.ThresholdDays, env.Age.Compliant)
	}
	if !env.Age.Created.Equal(created) {
		t.Errorf("Created = %v, want %v", env.Age.Created, created)
	}
	if len(env.Findings) != 1 || env.Findings[0].CVE != "CVE-1" {
		t.Fatalf("findings missing from envelope: %+v", env.Findings)
	}
}
