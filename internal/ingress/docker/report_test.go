package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

type fakeReports struct {
	findings []policy.Finding
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

type errReports struct{}

func (errReports) FindingsByPush(_ context.Context, _ string) ([]policy.Finding, error) {
	return nil, errors.New("audit store down")
}

func (errReports) FindingsByImageRef(_ context.Context, _, _ string) ([]policy.Finding, error) {
	return nil, errors.New("audit store down")
}

func TestReportEndpointReturnsFindings(t *testing.T) {
	rs := &fakeReports{findings: []policy.Finding{{CVE: "CVE-1", Severity: "CRITICAL", Pkg: "openssl"}}}
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var got []policy.Finding
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].CVE != "CVE-1" {
		t.Errorf("findings = %+v", got)
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
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/c3aiops:2.13.25-as", nil)
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
	rs := &fakeReports{}
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/e2e/app@sha256:deadbeef", nil)
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
	rs := &fakeReports{}
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/88824db0a4604bf48aad9ec246144d20", nil)
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
	h := NewHandler(fakeAuth{ok: false}, nil, nil, nil, "myreg.azurecr.io", rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	// no Authorization header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated report request: code = %d, want 401", rec.Code)
	}
}

func TestReportEndpointErrorIs500(t *testing.T) {
	rs := errReports{} // FindingsByPush returns an error
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("report store error: code = %d, want 500", rec.Code)
	}
}

func TestReportEndpointEmptyFindingsOK(t *testing.T) {
	rs := &fakeReports{findings: nil}
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("empty findings: code = %d, want 200", rec.Code)
	}
}
