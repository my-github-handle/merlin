package docker

import (
	"fmt"
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
	scratchBaseDir string
	regIssuer      *auth.RegistryTokenIssuer
	tokenRealm     string
	service        string
	tokenHandler   *TokenHandler
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

// SetScratchBaseDir configures the base directory for scratch dirs used during
// image assembly. When set, scratch dirs are created under this directory (typically
// a writable emptyDir mount). When empty (default), os.MkdirTemp creates scratch
// dirs in the system temp location.
func (h *Handler) SetScratchBaseDir(dir string) {
	h.scratchBaseDir = dir
}

// SetRegistryAuth switches /v2/ to verify Merlin's registry token (instead of a
// raw Entra token) and points the WWW-Authenticate realm at the /token endpoint.
func (h *Handler) SetRegistryAuth(issuer *auth.RegistryTokenIssuer, tokenRealm, service string) {
	h.regIssuer = issuer
	h.tokenRealm = tokenRealm
	h.service = service
}

// SetTokenHandler registers the GET /token endpoint.
func (h *Handler) SetTokenHandler(th *TokenHandler) {
	h.tokenHandler = th
	h.mux.HandleFunc("/token", th.ServeHTTP)
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
	if h.regIssuer != nil {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, _, err := h.regIssuer.Verify(bearer); err != nil {
			h.challenge(w, r)
			return false
		}
		return true
	}
	// Legacy path: validate the Entra token directly (pre-Phase-9 behavior).
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, err := h.auth.Validate(r.Context(), bearer); err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="merlin",service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

// challenge writes the Docker token-flow WWW-Authenticate pointing at /token.
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request) {
	repo := repoFromV2Path(r.URL.Path) // best-effort; "" if not a repo path
	scope := ""
	if repo != "" {
		scope = fmt.Sprintf(`,scope="repository:%s:push,pull"`, repo)
	}
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer realm="%s",service="%s"%s`, h.tokenRealm, h.service, scope))
	w.WriteHeader(http.StatusUnauthorized)
}

// repoFromV2Path extracts <repo> from /v2/<repo>/... paths (returns "" for bare /v2/).
func repoFromV2Path(path string) string {
	path = strings.TrimPrefix(path, "/v2/")
	if path == "" || path == "/" {
		return ""
	}
	// Extract repo before /manifests/, /blobs/, or any other Docker API path segment.
	for _, seg := range []string{"/manifests/", "/blobs/"} {
		if idx := strings.Index(path, seg); idx != -1 {
			return path[:idx]
		}
	}
	// If no known segment found, return the whole path (might be a plain repo name).
	return strings.TrimSuffix(path, "/")
}

// validatedIdentity returns the caller identity from the bearer token, using the
// same dual-mode logic as authenticate(): verify Merlin's registry token when
// registry auth is active, otherwise validate the Entra token (legacy path).
func (h *Handler) validatedIdentity(r *http.Request) (auth.Identity, bool) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if h.regIssuer != nil {
		subject, _, err := h.regIssuer.Verify(bearer)
		if err != nil {
			return auth.Identity{}, false
		}
		return auth.Identity{Subject: subject}, true
	}
	identity, err := h.auth.Validate(r.Context(), bearer)
	if err != nil {
		return auth.Identity{}, false
	}
	return identity, true
}

// handleUpload and handleManifest are implemented in upload.go / manifest.go.
