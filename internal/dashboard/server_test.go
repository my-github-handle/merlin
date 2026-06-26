package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testServer() http.Handler {
	svc := newTestService(fakeReader{})
	rnd, _ := NewRenderer()
	b := NewBroadcaster(4)
	return NewServer(svc, rnd, b, func() time.Time { return time.Unix(1750000000, 0) })
}

func TestServeActivityPage(t *testing.T) {
	srv := testServer()
	req := httptest.NewRequest("GET", "/?range=7d", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type=%q", ct)
	}
}

func TestServeBadRangeFallsBack(t *testing.T) {
	srv := testServer()
	req := httptest.NewRequest("GET", "/?range=bogus", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d (bad range should fall back, not error)", rec.Code)
	}
}

func TestReportByRefAndPushID(t *testing.T) {
	srv := testServer()
	for _, path := range []string{"/report?ref=a/b:v1", "/report?push_id=p1"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Errorf("%s status=%d", path, rec.Code)
		}
	}
}

func TestReportJSONContentType(t *testing.T) {
	srv := testServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/dashboard/report.json?ref=a/b:v1", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type=%q want application/json", ct)
	}
}

func TestStaticServed(t *testing.T) {
	srv := testServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/static/app.css", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "topbar") {
		t.Errorf("static css not served: status=%d", rec.Code)
	}
}
