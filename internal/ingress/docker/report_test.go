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

type fakeReports struct{ findings []policy.Finding }

func (f fakeReports) FindingsByPush(_ context.Context, _ string) ([]policy.Finding, error) {
	return f.findings, nil
}

type errReports struct{}

func (errReports) FindingsByPush(_ context.Context, _ string) ([]policy.Finding, error) {
	return nil, errors.New("audit store down")
}

func TestReportEndpointReturnsFindings(t *testing.T) {
	rs := fakeReports{findings: []policy.Finding{{CVE: "CVE-1", Severity: "CRITICAL", Pkg: "openssl"}}}
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

func TestReportEndpointRejectsUnauthenticated(t *testing.T) {
	rs := fakeReports{}
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
	rs := fakeReports{findings: nil}
	h := NewHandler(fakeAuth{ok: true}, nil, nil, nil, "myreg.azurecr.io", rs)
	req := httptest.NewRequest(http.MethodGet, "/reports/push-123", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("empty findings: code = %d, want 200", rec.Code)
	}
}
