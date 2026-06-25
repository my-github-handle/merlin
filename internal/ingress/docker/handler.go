package docker

import (
	"net/http"
	"strings"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
)

// Handler implements the inbound Docker Registry V2 surface.
type Handler struct {
	auth           auth.Authenticator
	store          *staging.Store
	router         *router.Router
	outcome        *Outcome
	registry       string
	reports        ReportSource
	mux            *http.ServeMux
	maxUploadBytes int64
	pool           *router.Pool
	gateTimeout    time.Duration
}

// NewHandler builds the V2 handler. reports backs GET /reports/<push_id>.
func NewHandler(a auth.Authenticator, st *staging.Store, r *router.Router, o *Outcome, registry string, reports ReportSource) *Handler {
	h := &Handler{auth: a, store: st, router: r, outcome: o, registry: registry, reports: reports, mux: http.NewServeMux()}
	h.mux.HandleFunc("/v2/", h.route)
	h.mux.HandleFunc("/reports/", h.handleReport)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// SetMaxUploadBytes configures the maximum upload chunk size (default 2 GiB).
func (h *Handler) SetMaxUploadBytes(n int64) {
	h.maxUploadBytes = n
}

func (h *Handler) getMaxUploadBytes() int64 {
	if h.maxUploadBytes == 0 {
		return 2 << 30 // 2 GiB default
	}
	return h.maxUploadBytes
}

// SetPool configures the gate pool for concurrent scan limiting.
func (h *Handler) SetPool(p *router.Pool) {
	h.pool = p
}

// SetGateTimeout configures the gate timeout (default 5 minutes when pool is used).
func (h *Handler) SetGateTimeout(d time.Duration) {
	h.gateTimeout = d
}

func (h *Handler) route(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(w, r) {
		return
	}
	// Base version check.
	if r.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	switch {
	case strings.Contains(r.URL.Path, "/blobs/uploads/"):
		if r.Method != http.MethodPost && r.Method != http.MethodPatch && r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.handleUpload(w, r)
	case strings.Contains(r.URL.Path, "/manifests/"):
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.handleManifest(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) bool {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, err := h.auth.Validate(r.Context(), bearer); err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="merlin",service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

// validatedIdentity re-validates the bearer token and returns the identity.
func (h *Handler) validatedIdentity(r *http.Request) (auth.Identity, bool) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	identity, err := h.auth.Validate(r.Context(), bearer)
	if err != nil {
		return auth.Identity{}, false
	}
	return identity, true
}

// handleUpload and handleManifest are implemented in upload.go / manifest.go.
