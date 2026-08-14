package docker

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/promote"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
	"github.com/merlin-gate/merlin/internal/tenant"
)

// Handler implements the inbound Docker Registry V2 surface.
type Handler struct {
	resolver       tenant.Resolver
	store          *staging.Store
	router         *router.Router
	outcome        *Outcome
	reports        ReportSource
	mux            *http.ServeMux
	maxUploadBytes int64
	uploadSlots    chan struct{}
	uploadWait     time.Duration
	pool           *router.Pool
	gateTimeout    time.Duration
	scratchBaseDir string
	regIssuer      *auth.RegistryTokenIssuer
	tokenRealm     string
	service        string
	tokenHandler   *TokenHandler
	promoter       promote.Promoter // nil = publish to ACR synchronously
	maxPending     int              // 0 = no admission bound on the promotion backlog
	requests       RequestObserver  // nil = no per-request counting (hermetic tests)
	// indexWait/indexPoll bound the retry of an image-index forward whose referenced
	// image is still being promoted. Zero means the defaults; only tests set them, to
	// avoid a real-time wait, so there is no operator knob to get wrong.
	indexWait time.Duration
	indexPoll time.Duration
}

// RequestObserver receives per-request telemetry. observability.Metrics satisfies
// it. It is a local interface for the same reason MetricsObserver is: it keeps the
// ingress package free of an observability import.
//
// It exists because every other counter in Merlin is decision-shaped, so a request
// answered BEFORE a decision exists — 401 at auth, 404 on an unknown host, 503 shed
// at the upload gate — is counted nowhere. Those are precisely the failures where
// the gate looks idle while clients are being turned away.
type RequestObserver interface {
	ObserveRequest(method, route, status string)
}

// SetRequestObserver wires per-request counting. Nil disables it. Safe to call only
// before the handler starts serving.
func (h *Handler) SetRequestObserver(o RequestObserver) { h.requests = o }

// SetPromoter defers ACR publication to a durable queue, so the manifest PUT is not
// held across the push. Nil keeps the synchronous push (hermetic tests,
// single-binary dev).
func (h *Handler) SetPromoter(p promote.Promoter) { h.promoter = p }

// SetMaxPendingPromotions bounds how many promotions may be waiting for the worker
// before a push is shed with 503 + Retry-After.
//
// This is a DISK bound. Deferring publication means the 201 goes out while the job
// is still queued, so each pending job pins an OCI layout plus an extracted rootfs
// on the scratch volume — a per-pod emptyDir — and the only thing limiting total
// scratch is the worker's drain rate. Under a slow ACR that is unbounded. Shedding a
// push is recoverable (docker retries); filling the volume fails every concurrent
// push at assemble time.
//
// n < 1 disables the check (the zero value, so callers that never configure it are
// unaffected). Safe to call only before the handler starts serving.
func (h *Handler) SetMaxPendingPromotions(n int) {
	if n < 1 {
		h.maxPending = 0
		return
	}
	h.maxPending = n
}

// DefaultMaxPendingPromotions bounds the promotion backlog when the operator has
// not configured one. Deliberately small: each pending job holds roughly twice the
// image size on the scratch emptyDir (the OCI layout keeps the compressed blobs, the
// rootfs holds them extracted), so a few dozen multi-GB images is already more than
// the volume holds.
const DefaultMaxPendingPromotions = 16

// promotionBacklogFull reports whether the promotion queue is at its bound.
//
// Fail-OPEN on an unreadable depth: the bound is a disk safeguard, and treating a
// Valkey blip as saturation would reject scanned, passing images — turning one flaky
// read into an outage of the gate itself.
func (h *Handler) promotionBacklogFull(r *http.Request) bool {
	if h.maxPending < 1 || h.promoter == nil {
		return false
	}
	counter, ok := h.promoter.(promote.PendingCounter)
	if !ok {
		return false
	}
	depth, err := counter.Pending(r.Context())
	if err != nil {
		log.Printf("promotion backlog unreadable, admitting push: %v", err)
		return false
	}
	return depth >= h.maxPending
}

// pushID generates the ID shared by the report URL, the audit row, and any
// promotion job. It reuses the Outcome's generator rather than adding a second
// source, so a test that stubs IDGen still controls all three.
func (h *Handler) pushID() string {
	if h.outcome != nil {
		return h.outcome.newPushID()
	}
	return generatePushID()
}

// NewHandler builds the V2 handler. reports backs GET /reports/<push_id>.
func NewHandler(resolver tenant.Resolver, st *staging.Store, r *router.Router, o *Outcome, reports ReportSource) *Handler {
	h := &Handler{resolver: resolver, store: st, router: r, outcome: o, reports: reports, mux: http.NewServeMux()}
	h.mux.HandleFunc("/v2/", h.route)
	h.mux.HandleFunc("/reports/", h.handleReport)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
	h.mux.ServeHTTP(sw, r)
	if h.requests != nil {
		// After the mux, so sw.status is the status actually written — including the
		// ones no handler in this package chose (mux 404s) and the ones written from
		// deep inside a helper (the upload gate's 503).
		h.requests.ObserveRequest(r.Method, routeClass(r.URL.Path), strconv.Itoa(sw.status))
	}
	log.Printf("v2 %s %s%s -> %d (%dB, %s)",
		r.Method, r.URL.Path, queryForLog(r.URL.RawQuery), sw.status, sw.written, time.Since(start).Round(time.Millisecond))
}

// routeClass maps a request path to a bounded label value.
//
// This is the cardinality guard, and it is load-bearing: a raw path carries the
// repo, the tag and often a digest, all attacker-or-CI controlled, so labelling
// paths would create a new permanent time series per image pushed and eventually
// take the scrape target down. Only these classes are ever emitted.
//
// Order matters: the upload path also contains "/blobs/", so blob_upload must be
// tested first, and the bounded /v2/ prefix must come last so it does not swallow
// the specific classes.
func routeClass(path string) string {
	switch {
	case path == "/v2/" || path == "/v2":
		return "base"
	case path == "/token":
		return "token"
	case strings.HasPrefix(path, "/reports/"):
		return "report"
	case strings.Contains(path, "/blobs/uploads/"):
		return "blob_upload"
	case strings.Contains(path, "/blobs/"):
		return "blob"
	case strings.Contains(path, "/manifests/"):
		return "manifest"
	case strings.HasPrefix(path, "/v2/"):
		return "v2_other"
	default:
		return "other"
	}
}

// statusWriter records the response status and byte count for request logging.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written int64
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.written += int64(n)
	return n, err
}

// queryForLog formats a raw query string for the access log (leading "?" or "").
func queryForLog(raw string) string {
	if raw == "" {
		return ""
	}
	return "?" + raw
}

// SetMaxUploadBytes configures the maximum upload chunk size (default 512 MiB).
func (h *Handler) SetMaxUploadBytes(n int64) {
	h.maxUploadBytes = n
}

// defaultMaxUploadBytes bounds a single upload request body when the operator has
// not configured a limit. Deliberately far below the pod memory limit: staging
// buffers the whole chunk AND the accumulated upload in memory, so the resident
// cost is a multiple of this number, times the number of concurrent uploads (see
// SetUploadConcurrency). The former 2 GiB default could not be absorbed by any
// limit merlin runs under.
const defaultMaxUploadBytes = 512 << 20 // 512 MiB

func (h *Handler) getMaxUploadBytes() int64 {
	if h.maxUploadBytes == 0 {
		return defaultMaxUploadBytes
	}
	return h.maxUploadBytes
}

// SetUploadConcurrency caps how many blob-upload requests may buffer bytes at once.
//
// This is a MEMORY bound, not a fairness one: staging.WriteChunk and CompleteBlob
// read the accumulated upload back, append, and re-Put it, so an in-flight upload
// holds several times the chunk size resident. Nothing else bounded that — only the
// manifest gate acquires the scan pool — so N concurrent pushes cost N x that, which
// is how the pods reached their memory limit and were OOMKilled. The scan pool is
// deliberately NOT reused: it is sized for Grype CPU, and sharing it would make
// uploads and scans starve each other.
//
// n < 1 disables the limit (the zero value, so callers that never configure it are
// unaffected). Safe to call only before the handler starts serving.
func (h *Handler) SetUploadConcurrency(n int) {
	if n < 1 {
		h.uploadSlots = nil
		return
	}
	h.uploadSlots = make(chan struct{}, n)
}

// SetUploadWait bounds how long an upload queues for a slot before it is answered
// with 503 + Retry-After. Zero uses defaultUploadWait.
func (h *Handler) SetUploadWait(d time.Duration) {
	h.uploadWait = d
}

// defaultUploadWait keeps a queued upload waiting long enough that a normal push
// burst is absorbed rather than rejected, while still failing fast enough that a
// docker client retries instead of hanging on a stalled connection.
const defaultUploadWait = 30 * time.Second

// acquireUploadSlot blocks until an upload slot is free, the wait budget expires, or
// the client disconnects. The returned release func is nil when no limit is set.
// ok=false means the caller has already answered the request and must return.
func (h *Handler) acquireUploadSlot(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	if h.uploadSlots == nil {
		return func() {}, true
	}
	wait := h.uploadWait
	if wait == 0 {
		wait = defaultUploadWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case h.uploadSlots <- struct{}{}:
		return func() { <-h.uploadSlots }, true
	case <-timer.C:
		// Saturated: shed load with a retryable status rather than admitting the
		// upload and risking an OOMKill that fails every concurrent push.
		w.Header().Set("Retry-After", "5")
		http.Error(w, "upload capacity saturated", http.StatusServiceUnavailable)
		return nil, false
	case <-r.Context().Done():
		// Client gave up while queued; there is no one left to answer.
		return nil, false
	}
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
	// Resolve the tenant from the request host first: an unknown host/prefix is a
	// 404 (before auth), so an unrecognized registry cannot probe the auth surface.
	t, err := h.resolver.ForHost(r.Host)
	if err != nil {
		http.Error(w, "unknown registry", http.StatusNotFound)
		return
	}
	if !h.authenticate(w, r, t) {
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
		switch r.Method {
		case http.MethodPut:
			h.handleManifest(w, r, t)
		case http.MethodGet, http.MethodHead:
			// Docker issues a GET/HEAD manifest existence check during push. Merlin
			// is a push gate, not a pull-through registry, so it holds no manifest
			// until one passes the gate and is forwarded to ACR. Report 404 (not
			// 405) so the docker client proceeds with the upload+PUT.
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, t *tenant.Tenant) bool {
	if h.regIssuer != nil {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		// The registry token carries a prefix claim bound to the tenant it was minted
		// for; a token minted for one tenant presented to another is rejected (401).
		_, _, prefix, err := h.regIssuer.Verify(bearer)
		if err != nil || prefix != t.Prefix {
			h.challenge(w, r)
			return false
		}
		return true
	}
	// Legacy path: validate the Entra token directly against the tenant's authn.
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, err := t.Authn.Validate(r.Context(), bearer); err != nil {
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
func (h *Handler) validatedIdentity(r *http.Request, t *tenant.Tenant) (auth.Identity, bool) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if h.regIssuer != nil {
		subject, _, _, err := h.regIssuer.Verify(bearer)
		if err != nil {
			return auth.Identity{}, false
		}
		return auth.Identity{Subject: subject}, true
	}
	identity, err := t.Authn.Validate(r.Context(), bearer)
	if err != nil {
		return auth.Identity{}, false
	}
	return identity, true
}

// handleUpload and handleManifest are implemented in upload.go / manifest.go.
