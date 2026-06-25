package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

type fakeReports struct{ findings []policy.Finding }

func (f fakeReports) FindingsByPush(_ context.Context, _ string) ([]policy.Finding, error) {
	return f.findings, nil
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
