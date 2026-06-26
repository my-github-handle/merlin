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

func TestServeOverview(t *testing.T) {
	srv := testServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/?range=7d", nil))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("overview status=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	// verify it's the overview page, not old activity
	body := rec.Body.String()
	if !strings.Contains(body, "Images") {
		t.Errorf("overview page missing 'Images' marker")
	}
}

func TestImagesJSON(t *testing.T) {
	srv := testServer()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/dashboard/images?range=7d&page=1&crit=1&rejected=1", nil))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("images json status=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestRemovedRoutesServeOverview(t *testing.T) {
	srv := testServer()
	for _, p := range []string{"/health", "/vulnerabilities", "/identities"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		// "/" is the catch-all overview; removed routes must NOT 200 as their old pages.
		// They now fall through to overview (200) OR 404. Assert they no longer render
		// their old page — accept 200 (overview catch-all) but body must be the overview.
		if rec.Code != 200 {
			t.Errorf("%s status=%d", p, rec.Code)
		}
		// verify it's the overview page, not the old dedicated page
		body := rec.Body.String()
		if !strings.Contains(body, "Images") {
			t.Errorf("%s should serve overview page with 'Images' marker", p)
		}
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
