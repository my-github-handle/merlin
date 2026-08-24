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

// HandlerConfig is everything a Handler is built from: five collaborators and eleven
// knobs, all supplied in one place.
//
// It replaced a positional constructor followed by up to eleven setters. That was not
// merely verbose: the handler was reachable in a partially configured state, no knob's
// precondition was checked anywhere, and a knob whose precondition was unmet did
// nothing AT ALL — no error, no log. A promotion bound with no promoter, an upload
// wait with no slots, a registry issuer with an empty realm: each of those is a value
// in a ConfigMap that an operator would reasonably believe is in force. New validates
// the couplings once, up front, where a mistake costs a startup failure instead of a
// silent gap.
//
// The zero value of every optional field is the unconfigured behaviour, so a caller
// fills in only what it needs.
type HandlerConfig struct {
	// Resolver binds a request Host to its tenant. REQUIRED: this mapping is the
	// security boundary — it decides which ACR a push may reach and whose Entra
	// surface authenticates it.
	Resolver tenant.Resolver

	// Router runs the policy gate. Nil is legal (the report-only and auth-only
	// surfaces never reach it) but a manifest PUT without one cannot be gated.
	Router *router.Router

	// Outcome turns a gate result into a response, an audit row and a report URL.
	Outcome *Outcome

	// Store holds staged blobs. Nil is the hermetic wiring: no push can complete.
	Store *staging.Store

	// Reports backs GET /reports/<push_id>. Nil serves 404 there.
	Reports ReportSource

	// Requests receives per-request telemetry. Nil disables it — which is what the
	// hermetic build wants and what production must never have, since requests
	// answered before a decision exists (401, 404, shed 503) are counted nowhere
	// else.
	Requests RequestObserver

	// Promoter defers ACR publication to a durable queue. Nil keeps the synchronous
	// push, which holds the manifest PUT across the ACR upload.
	Promoter promote.Promoter

	// MaxPendingPromotions bounds the promotion backlog; a push beyond it is shed
	// with 503 + Retry-After.
	//
	// This is a DISK bound, not a fairness one. Deferring publication means the 201
	// goes out while the job is still queued, so each pending job pins an OCI layout
	// plus an extracted rootfs on the scratch volume — a per-pod emptyDir — and the
	// only thing limiting total scratch is the worker's drain rate, which under a slow
	// ACR is unbounded. Shedding a push is recoverable (docker retries); filling the
	// volume fails every concurrent push at assemble time.
	//
	// Zero means unbounded. Requires Promoter — a bound with nothing to count is
	// rejected rather than ignored.
	MaxPendingPromotions int

	// MaxUploadBytes caps one upload request body. Zero uses
	// defaultMaxUploadBytes.
	MaxUploadBytes int64

	// UploadConcurrency caps how many blob uploads may buffer bytes at once.
	//
	// This is a MEMORY bound, not a fairness one: staging.WriteChunk and CompleteBlob
	// read the accumulated upload back, append, and re-Put it, so an in-flight upload
	// holds several times the chunk size resident. Nothing else bounded that — only the
	// manifest gate acquires the scan Pool — so N concurrent pushes cost N times that,
	// which is how these pods reached their memory limit and were OOMKilled. The scan
	// Pool is deliberately NOT reused: it is sized for Grype CPU, and sharing it would
	// make uploads and scans starve each other.
	//
	// Zero means unbounded.
	UploadConcurrency int

	// UploadWait bounds how long an upload queues for a slot before 503 +
	// Retry-After. Zero uses defaultUploadWait. Requires UploadConcurrency: without
	// slots there is no queue, so a wait budget would be inert.
	UploadWait time.Duration

	// Pool bounds concurrent scans. Nil gates on Router directly, with no limit.
	Pool *router.Pool

	// GateTimeout budgets ONE phase of the gate — the slot wait and the scan get this
	// budget each, so a slot that frees late still gets a full scan window. Zero uses
	// defaultGateTimeout. Independent of Pool: it bounds the scan even with no pool.
	GateTimeout time.Duration

	// ScratchBaseDir is where assembly scratch dirs are created. Empty uses the
	// system temp dir, which in this deployment is not the volume sized for it.
	ScratchBaseDir string

	// RegistryIssuer switches /v2/ from validating a raw Entra token to verifying
	// Merlin's own registry token. Setting it REQUIRES TokenRealm and Service: they
	// are what the WWW-Authenticate challenge advertises, and a client that receives
	// an empty realm has nowhere to fetch a token from, so the whole push flow stops
	// with no error anywhere in Merlin.
	RegistryIssuer *auth.RegistryTokenIssuer

	// TokenRealm is the absolute URL the challenge points at. It need not be served
	// by this handler — that is why a nil TokenHandler alongside a RegistryIssuer is
	// allowed rather than rejected.
	TokenRealm string

	// Service is the Docker auth `service` value in the challenge.
	Service string

	// TokenHandler registers GET /token on this handler's mux. Nil leaves the route
	// unregistered.
	TokenHandler *TokenHandler
}

// New builds the V2 handler from a validated config.
func New(cfg HandlerConfig) (*Handler, error) {
	if cfg.Resolver == nil {
		return nil, fmt.Errorf("docker handler: Resolver is required (host->tenant resolution is the security boundary)")
	}
	if cfg.RegistryIssuer != nil && (cfg.TokenRealm == "" || cfg.Service == "") {
		return nil, fmt.Errorf("docker handler: RegistryIssuer set with TokenRealm=%q Service=%q — the WWW-Authenticate challenge would tell clients nowhere to get a token", cfg.TokenRealm, cfg.Service)
	}
	if cfg.MaxPendingPromotions > 0 && cfg.Promoter == nil {
		return nil, fmt.Errorf("docker handler: MaxPendingPromotions=%d with no Promoter — the backlog bound would be inert", cfg.MaxPendingPromotions)
	}
	if cfg.UploadWait > 0 && cfg.UploadConcurrency < 1 {
		return nil, fmt.Errorf("docker handler: UploadWait=%s with no UploadConcurrency — there is no queue to wait in, so the budget would be inert", cfg.UploadWait)
	}

	h := &Handler{
		resolver:       cfg.Resolver,
		store:          cfg.Store,
		router:         cfg.Router,
		outcome:        cfg.Outcome,
		reports:        cfg.Reports,
		mux:            http.NewServeMux(),
		requests:       cfg.Requests,
		promoter:       cfg.Promoter,
		maxUploadBytes: cfg.MaxUploadBytes,
		uploadWait:     cfg.UploadWait,
		pool:           cfg.Pool,
		gateTimeout:    cfg.GateTimeout,
		scratchBaseDir: cfg.ScratchBaseDir,
		regIssuer:      cfg.RegistryIssuer,
		tokenRealm:     cfg.TokenRealm,
		service:        cfg.Service,
		tokenHandler:   cfg.TokenHandler,
	}
	if cfg.MaxPendingPromotions > 0 {
		h.maxPending = cfg.MaxPendingPromotions
	}
	if cfg.UploadConcurrency > 0 {
		h.uploadSlots = make(chan struct{}, cfg.UploadConcurrency)
	}
	h.mux.HandleFunc("/v2/", h.route)
	h.mux.HandleFunc("/reports/", h.handleReport)
	if cfg.TokenHandler != nil {
		h.mux.HandleFunc("/token", cfg.TokenHandler.ServeHTTP)
	}
	return h, nil
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

// defaultMaxUploadBytes bounds a single upload request body when the operator has
// not configured a limit. Deliberately far below the pod memory limit: staging
// buffers the whole chunk AND the accumulated upload in memory, so the resident
// cost is a multiple of this number, times the number of concurrent uploads (see
// HandlerConfig.UploadConcurrency). The former 2 GiB default could not be absorbed by any
// limit merlin runs under.
const defaultMaxUploadBytes = 512 << 20 // 512 MiB

func (h *Handler) getMaxUploadBytes() int64 {
	if h.maxUploadBytes == 0 {
		return defaultMaxUploadBytes
	}
	return h.maxUploadBytes
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
