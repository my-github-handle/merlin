package docker

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// spyRequests records ObserveRequest calls as "method route status".
type spyRequests struct {
	mu   sync.Mutex
	seen []string
}

func (s *spyRequests) ObserveRequest(method, route, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, method+" "+route+" "+status)
}

func (s *spyRequests) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func TestRouteClassIsBounded(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/v2/", "base"},
		{"/v2", "base"},
		{"/token", "token"},
		{"/reports/9f2c1b", "report"},
		{"/v2/team/app/blobs/uploads/abc-123", "blob_upload"},
		{"/v2/team/app/blobs/sha256:deadbeef", "blob"},
		{"/v2/team/app/manifests/v1.2.3", "manifest"},
		{"/v2/team/app/manifests/sha256:deadbeef", "manifest"},
		{"/v2/team/app/tags/list", "v2_other"},
		{"/healthz", "other"},
		{"", "other"},
	}
	for _, tc := range tests {
		if got := routeClass(tc.path); got != tc.want {
			t.Errorf("routeClass(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestRouteClassDropsRepoAndReference is the cardinality guard: the label must not
// carry anything an image push controls, or every tag and digest ever pushed becomes
// its own permanent time series.
func TestRouteClassDropsRepoAndReference(t *testing.T) {
	a := routeClass("/v2/team-a/app/manifests/sha256:aaaa")
	b := routeClass("/v2/team-b/other/manifests/v9")
	if a != b {
		t.Errorf("distinct repos/refs produced distinct classes: %q vs %q", a, b)
	}
}

// TestObservesRequestOnAuthFailure is the reason this metric exists: a 401 is
// answered before any gate decision exists, so no decision counter sees it. Before
// this counter, a tenant whose credentials had expired produced a silent gate.
func TestObservesRequestOnAuthFailure(t *testing.T) {
	sr := &spyRequests{}
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: false}), Requests: sr})

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = testTenantHost
	h.ServeHTTP(httptest.NewRecorder(), req)

	want := "GET base 401"
	got := sr.calls()
	if len(got) != 1 || got[0] != want {
		t.Errorf("ObserveRequest = %v, want [%q]", got, want)
	}
}

func TestObservesRequestOnSuccess(t *testing.T) {
	sr := &spyRequests{}
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), Requests: sr})

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	h.ServeHTTP(httptest.NewRecorder(), req)

	want := "GET base 200"
	got := sr.calls()
	if len(got) != 1 || got[0] != want {
		t.Errorf("ObserveRequest = %v, want [%q]", got, want)
	}
}

// TestObservesRequestOnUnknownHost covers the pre-auth 404: an unrecognized host
// is rejected before the tenant is known, which is exactly the shape of a
// misconfigured DNS record or an ingress pointed at the wrong service.
func TestObservesRequestOnUnknownHost(t *testing.T) {
	sr := &spyRequests{}
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), Requests: sr})

	req := httptest.NewRequest(http.MethodPut, "/v2/team/app/manifests/v1", nil)
	req.Host = "not-a-tenant.example.com"
	h.ServeHTTP(httptest.NewRecorder(), req)

	want := "PUT manifest 404"
	got := sr.calls()
	if len(got) != 1 || got[0] != want {
		t.Errorf("ObserveRequest = %v, want [%q]", got, want)
	}
}

func TestNilRequestObserverIsSafe(t *testing.T) {
	h := mustNewHandler(t, HandlerConfig{Resolver: testResolver("myreg.azurecr.io", nil, fakeAuth{ok: true}), Requests: nil})
	// Requests omitted from the config entirely, then set to an explicit nil.

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = testTenantHost
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200 with no request observer", rec.Code)
	}
}
