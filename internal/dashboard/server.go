package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
)

// Server is the dashboard HTTP handler (UI + JSON API).
type Server struct {
	svc *Service
	rnd *Renderer
	b   *Broadcaster
	now func() time.Time
	mux *http.ServeMux
}

// queryTimeout bounds every ClickHouse-backed request.
const queryTimeout = 5 * time.Second

// NewServer wires routes and returns the handler.
func NewServer(svc *Service, rnd *Renderer, b *Broadcaster, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	s := &Server{svc: svc, rnd: rnd, b: b, now: now, mux: http.NewServeMux()}
	s.mux.HandleFunc("/", s.handleOverview) // catch-all -> overview
	s.mux.HandleFunc("/report", s.handleReport)
	s.mux.HandleFunc("/api/dashboard/images", s.handleImagesJSON)
	s.mux.HandleFunc("/api/dashboard/report.json", s.handleReportJSON)
	s.mux.HandleFunc("/api/dashboard/stream", s.handleStream)
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(StaticFS()))))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) ctx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), queryTimeout)
}

func (s *Server) rangeParam(r *http.Request) Range {
	rng, _ := ParseRange(r.URL.Query().Get("range"), s.now())
	return rng
}

func (s *Server) renderPage(w http.ResponseWriter, page string, vm any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.rnd.Render(w, page, vm)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	// honor ?page= on the catch-all overview (filter via the images endpoint/AJAX)
	vm, _ := s.svc.Overview(ctx, s.rangeParam(r))
	if p := pageParam(r); p > 1 {
		// re-fetch the requested page with current filter for server-rendered paging
		f := imageFilter(r)
		iv, _ := s.svc.Images(ctx, s.rangeParam(r), f, p)
		vm.Images, vm.Page, vm.Total, vm.HasPrev, vm.HasNext = iv.Images, iv.Page, iv.Total, iv.HasPrev, iv.HasNext
	}
	s.renderPage(w, "overview", vm)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	vm := s.reportVM(ctx, r)
	s.renderPage(w, "report", vm)
}

// reportVM resolves a report from ?push_id= or ?ref=repo:tag|repo@sha256.
func (s *Server) reportVM(ctx context.Context, r *http.Request) ReportVM {
	q := r.URL.Query()
	if pid := q.Get("push_id"); pid != "" {
		vm, _ := s.svc.Report(ctx, "", "", pid)
		return vm
	}
	repo, ref, ok := splitImageRef(q.Get("ref"))
	if !ok {
		return ReportVM{Found: false}
	}
	vm, _ := s.svc.Report(ctx, repo, ref, "")
	return vm
}

func (s *Server) handleImagesJSON(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	vm, _ := s.svc.Images(ctx, s.rangeParam(r), imageFilter(r), pageParam(r))
	writeJSON(w, vm)
}

func (s *Server) handleReportJSON(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	vm := s.reportVM(ctx, r)
	writeJSON(w, vm.Findings)
}

// handleStream is the SSE endpoint for the live feed.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch, cancel := s.b.Subscribe()
	defer cancel()
	enc := json.NewEncoder(noNewline{w})
	for {
		select {
		case <-r.Context().Done():
			return
		case d, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write([]byte("data: ")); err != nil {
				return
			}
			if err := enc.Encode(sseDecision{
				PushID: d.PushID, Repo: d.Repo, Tag: d.Tag, Digest: d.Digest,
				Identity: d.Identity, Passed: d.Passed, Reasons: d.Reasons,
			}); err != nil {
				return
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// sseDecision is the JSON shape pushed to the browser (lowercase keys for app.js).
type sseDecision struct {
	PushID   string   `json:"push_id"`
	Repo     string   `json:"repo"`
	Tag      string   `json:"tag"`
	Digest   string   `json:"digest"`
	Identity string   `json:"identity"`
	Passed   bool     `json:"passed"`
	Reasons  []string `json:"reasons"`
}

// noNewline lets json.Encoder write without its trailing newline interfering with
// SSE framing (we add our own "\n").
type noNewline struct {
	w interface{ Write([]byte) (int, error) }
}

func (n noNewline) Write(p []byte) (int, error) {
	p = []byte(strings.TrimRight(string(p), "\n"))
	return n.w.Write(p)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ") // pretty-print (matches the /reports contract)
	_ = enc.Encode(v)
}

// splitImageRef parses repo:tag or repo@sha256 (mirrors ingress/docker/report.go).
// Returns ok=false when the value is empty or has no tag/digest separator.
func splitImageRef(id string) (repo, ref string, ok bool) {
	if id == "" {
		return "", "", false
	}
	if at := strings.Index(id, "@"); at != -1 {
		return id[:at], id[at+1:], true
	}
	slash := strings.LastIndex(id, "/")
	lastColon := strings.LastIndex(id, ":")
	if lastColon > slash {
		return id[:lastColon], id[lastColon+1:], true
	}
	return "", "", false
}

func pageParam(r *http.Request) int {
	if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && n > 0 {
		return n
	}
	return 1
}

func imageFilter(r *http.Request) audit.ImageFilter {
	q := r.URL.Query()
	return audit.ImageFilter{
		Text:         q.Get("q"),
		HasCritical:  q.Get("crit") == "1",
		RejectedOnly: q.Get("rejected") == "1",
	}
}
