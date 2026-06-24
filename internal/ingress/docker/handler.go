package docker

import (
	"net/http"
	"strings"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
)

// Handler implements the inbound Docker Registry V2 surface.
type Handler struct {
	auth     auth.Authenticator
	store    *staging.Store
	router   *router.Router
	outcome  *Outcome
	registry string
	mux      *http.ServeMux
}

// NewHandler builds the V2 handler.
func NewHandler(a auth.Authenticator, st *staging.Store, r *router.Router, o *Outcome, registry string) *Handler {
	h := &Handler{auth: a, store: st, router: r, outcome: o, registry: registry, mux: http.NewServeMux()}
	h.mux.HandleFunc("/v2/", h.route)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

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
		h.handleUpload(w, r)
	case strings.Contains(r.URL.Path, "/manifests/"):
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

// handleUpload and handleManifest are implemented in upload.go / manifest.go.
