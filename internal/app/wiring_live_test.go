//go:build integration

package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/config"
)

// BuildWithBackends is 61.5% of this package's statements and cannot be entered at all
// without live clients: NewValkeySessionStoreWithTTL pings, and NewClickHouseWriter
// bootstraps the schema. So this suite is the only thing that covers the production
// wiring path, and `mage testAppWiring` is the only way to run it with its backends
// present.
//
// TWO LESSONS FROM R3 ARE BUILT IN HERE, both learned the expensive way:
//
//  1. A skip that exits 0 is indistinguishable from a pass. internal/promote's
//     conformance suite sat behind this same tag for weeks while `mage integration`
//     supplied no backend, so it skipped silently and the target went green over 30
//     uncovered statements of the Lua that makes Claim atomic. Hence requireBackends
//     FAILS rather than skips when the addresses are absent.
//  2. The test backend must match production's behaviour, not merely its name. A
//     non-cluster Valkey accepted promote's multi-key EVALs happily while CROSSSLOT
//     was live in production. The ClickHouse analogue bit during this very session:
//     24.10 REJECTS this schema's `TTL ts + INTERVAL n DAY` on a DateTime64(3) column
//     ("TTL expression result column should have DateTime or Date type"), while
//     production's 26.7 accepts it. A test on the older image would have failed for a
//     reason that does not exist in production. mage testAppWiring pins 26.7.
//
// EVERY ASSERTION HERE GOES THROUGH THE RETURNED SURFACE, never a private field.
// That is deliberate and is the whole point of R0 as a net for R1: R1 changes HOW the
// wiring is expressed (one constructor, a Servers struct, a HandlerConfig instead of
// 11 setters). A test that pokes at handler internals would have to be rewritten by
// the refactor it is supposed to be guarding — which, per the plan's own ground rule,
// would mean it was never a refactor. A test that asserts what the built servers DO
// survives any internal reshuffle.

const (
	valkeyAddrEnv = "MERLIN_VALKEY_ADDR"
	clickhouseEnv = "MERLIN_CLICKHOUSE_DSN"
)

// requireBackends fails rather than skips. See lesson 1 above.
func requireBackends(t *testing.T) (valkey, dsn string) {
	t.Helper()
	valkey, dsn = os.Getenv(valkeyAddrEnv), os.Getenv(clickhouseEnv)
	if valkey == "" || dsn == "" {
		t.Fatalf("%s and %s must both be set — run `mage testAppWiring`.\n"+
			"This is a FAILURE and not a skip on purpose: a silently skipped suite is why "+
			"internal/promote sat at a reported 64.4%% while its queue conformance tests ran "+
			"against nothing at all.", valkeyAddrEnv, clickhouseEnv)
	}
	return valkey, dsn
}

// jwksServer serves a syntactically valid JWK Set so auth.NewEntraKeyfunc can complete
// its initial fetch locally. The key is never used to verify a token here — the
// question this suite asks is whether the keyfunc is CONSTRUCTED and reaches the
// authenticator, not whether RS256 works (internal/auth covers that).
func jwksServer(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// fakeWorkloadIdentity satisfies azidentity.NewWorkloadIdentityCredential, which reads
// its tenant, client and token-file from the environment and fails at CONSTRUCTION if
// they are absent. No token is ever exchanged: the credential is lazy, so a placeholder
// file is enough to build the ACR pusher.
func fakeWorkloadIdentity(t *testing.T) {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "federated-token")
	if err := os.WriteFile(tok, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	t.Setenv("AZURE_CLIENT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tok)
}

// liveConfig is prodConfig pointed at the local backends. Each test gets its OWN
// ClickHouse database, which works because NewClickHouseWriter runs
// `CREATE DATABASE IF NOT EXISTS` on a separate connection to `default` before
// bootstrapping. That isolation is what lets the schema bootstrap be exercised for
// real in every test rather than being a no-op after the first one.
func liveConfig(t *testing.T, db string) config.Config {
	t.Helper()
	valkey, dsn := requireBackends(t)
	fakeWorkloadIdentity(t)

	cfg := prodConfig()
	cfg.Tenants[0].Auth.JWKSURL = jwksServer(t)
	cfg.Staging.ValkeyAddr = valkey
	cfg.Staging.SessionTTL = "1h"
	cfg.Staging.ScratchDir = t.TempDir()
	cfg.Audit.ClickHouseDSN = withDatabase(dsn, db)
	cfg.Server.DashboardAddr = "off"
	return cfg
}

// withDatabase swaps the database component of a ClickHouse DSN. Written by hand
// rather than with a string replace on the expected name: a replace that silently
// fails to match would point every test at ONE database, and the tests would still
// pass while no longer being isolated.
func withDatabase(dsn, db string) string {
	i := strings.LastIndex(dsn, "/")
	if i < 0 {
		return dsn + "/" + db
	}
	return dsn[:i+1] + db
}

// TestLiveWiringBuildsEveryServerAtItsConfiguredAddress pins each server to its own
// configured address. It was written against the positional return, where three bare
// *http.Server values in a row meant swapping two compiled cleanly and would serve
// the dashboard, which has NO auth, on the gate port; distinct ports caught that swap.
// Servers has since made the swap unnameable, but the addresses still have to come
// from the right config fields, and that is what remains under test.
func TestLiveWiringBuildsEveryServerAtItsConfiguredAddress(t *testing.T) {
	cfg := liveConfig(t, "merlin_wiring_addrs")
	cfg.Server.Addr = ":15001"
	cfg.Server.MetricsAddr = ":15002"
	cfg.Server.DashboardAddr = ":15003"

	built, err := BuildWithBackends(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer built.Close()

	for _, tc := range []struct {
		name string
		srv  *http.Server
		want string
	}{
		{"gate", built.Gate, ":15001"},
		{"metrics", built.Metrics, ":15002"},
		{"dashboard", built.Dashboard, ":15003"},
	} {
		if tc.srv == nil {
			t.Fatalf("%s server is nil", tc.name)
		}
		if tc.srv.Addr != tc.want {
			t.Errorf("%s server address = %q, want %q (a swapped return would serve the unauthenticated dashboard on the gate port)", tc.name, tc.srv.Addr, tc.want)
		}
		if tc.srv.Handler == nil {
			t.Errorf("%s server has no handler", tc.name)
		}
	}
}

// gateRequest builds a request whose Host names a CONFIGURED TENANT. This is not
// boilerplate: routing is per-tenant by Host (`<prefix>.<acr.baseDomain>`), and a
// request for any other host is 404, not 401. Discovered by this suite failing with
// 404 — which is the correct answer to an unrecognised host and is pinned as its own
// case below, because a gate that answered 401 to unknown hosts would be inviting
// credentials for a tenant it does not serve.
func gateRequest(cfg config.Config, method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = cfg.Tenants[0].Prefix + "." + cfg.ACR.BaseDomain
	return r
}

// TestLiveWiringRoutesByTenantHost pins the routing rule the helper above depends on.
func TestLiveWiringRoutesByTenantHost(t *testing.T) {
	cfg := liveConfig(t, "merlin_wiring_hosts")
	built, err := BuildWithBackends(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer built.Close()

	t.Run("configured tenant host challenges", func(t *testing.T) {
		rec := httptest.NewRecorder()
		built.Gate.Handler.ServeHTTP(rec, gateRequest(cfg, http.MethodGet, "/v2/"))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET /v2/ on %s.%s = %d, want 401", cfg.Tenants[0].Prefix, cfg.ACR.BaseDomain, rec.Code)
		}
	})

	t.Run("unknown host is 404, never a challenge", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		r.Host = "not-a-tenant.c3ci.cloud"
		built.Gate.Handler.ServeHTTP(rec, r)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET /v2/ on an unconfigured host = %d, want 404: issuing a 401 challenge would solicit credentials for a tenant this gate does not serve", rec.Code)
		}
	})
}

// TestLiveWiringToleratesAnUnreachableJWKSAtBoot pins a behaviour that surprised this
// suite: an unreachable JWKS endpoint does NOT fail the build. keyfunc.NewDefaultCtx
// logs the failed refresh and keeps retrying in the background, so the gate starts and
// simply rejects every token until the set loads. That is still fail-closed — closed at
// REQUEST time rather than at boot — and it is the better behaviour for a transient DNS
// blip during a rollout.
//
// Worth recording for a second reason: three pods restarted with exit 2 during the
// 46f0ce5 rollout carrying exactly this "Failed to refresh HTTP JWK Set" message. Since
// construction demonstrably survives it, that exit came from somewhere else, and this
// test is the evidence that the keyfunc is not the culprit.
func TestLiveWiringToleratesAnUnreachableJWKSAtBoot(t *testing.T) {
	cfg := liveConfig(t, "merlin_wiring_jwksdown")
	cfg.Tenants[0].Auth.JWKSURL = "http://127.0.0.1:1/keys"

	built, err := BuildWithBackends(context.Background(), cfg)
	if err != nil {
		t.Fatalf("an unreachable JWKS must not stop the gate from starting: %v", err)
	}
	defer built.Close()

	// Still fail-closed: the challenge is issued, but no token can validate.
	rec := httptest.NewRecorder()
	built.Gate.Handler.ServeHTTP(rec, gateRequest(cfg, http.MethodGet, "/v2/"))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /v2/ = %d, want 401", rec.Code)
	}
}

// TestLiveWiringGateChallengeCarriesConfig proves three separate config values reach
// the wire through the Docker auth challenge: ExternalURL (as the realm), Auth.Service,
// and the fact that the issuer/realm/token-handler fields were filled at all. A push client reads
// this header to find the token endpoint, so if it is wrong or absent every `docker
// push` fails at authentication — and the AppGW health probe, which expects exactly
// 401 on /v2/, marks the backend unhealthy and returns 502.
func TestLiveWiringGateChallengeCarriesConfig(t *testing.T) {
	cfg := liveConfig(t, "merlin_wiring_challenge")
	cfg.Server.ExternalURL = "https://gate.example.test"
	cfg.Auth.Service = "merlin-under-test"

	built, err := BuildWithBackends(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer built.Close()

	rec := httptest.NewRecorder()
	built.Gate.Handler.ServeHTTP(rec, gateRequest(cfg, http.MethodGet, "/v2/"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v2/ = %d, want 401 (the AppGW health probe expects exactly 401; anything else marks the backend unhealthy -> 502)", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	for _, want := range []string{
		`realm="https://gate.example.test/token"`,
		`service="merlin-under-test"`,
	} {
		if !strings.Contains(challenge, want) {
			t.Errorf("WWW-Authenticate = %q, want it to contain %s", challenge, want)
		}
	}
}

// TestLiveWiringMetricsServerExposesMerlinMetrics closes the loop that was open until
// 2026-08-13: /metrics was served and scraped by nobody, so every counter lived in the
// pod's memory and was lost on each restart — which is why the OOMKill history had to
// be reconstructed from audit rows. The registry is built once and shared by the
// policies, the outcome and the promotion worker, so an empty /metrics means the
// metrics server got a DIFFERENT registry than the components that record into it.
// It asserts a RECORDED VALUE, not the presence of a metric name. That distinction is
// the whole test: an earlier version checked that `merlin_promote_pending` appeared in
// the output, and it passed happily when the metrics server was handed a brand-new
// registry — because constructing metrics over any registry registers the same names,
// all reading zero. Only a counter that some other component incremented can
// distinguish a shared registry from a separate one.
func TestLiveWiringMetricsServerExposesMerlinMetrics(t *testing.T) {
	cfg := liveConfig(t, "merlin_wiring_metrics")
	built, err := BuildWithBackends(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer built.Close()

	// Drive the GATE, then scrape the METRICS server. The request observer lives on
	// the docker handler; the scrape reads the registry. If those are not the same
	// registry, the counter below is absent or zero.
	built.Gate.Handler.ServeHTTP(httptest.NewRecorder(), gateRequest(cfg, http.MethodGet, "/v2/"))

	rec := httptest.NewRecorder()
	built.Metrics.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	if !hasPositiveSample(rec.Body.String(), "merlin_requests_total") {
		t.Errorf("no positive merlin_requests_total sample after a gate request — the metrics server and the request observer hold different registries, so every counter the gate records is scraped as zero forever:\n%s", rec.Body.String())
	}
}

// hasPositiveSample reports whether any sample of the named metric carries a value
// above zero. Zero-valued samples are ignored on purpose: a registered-but-never-
// incremented metric is exactly the false positive this helper exists to reject.
func hasPositiveSample(body, metric string) bool {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, metric+"{") && !strings.HasPrefix(line, metric+" ") {
			continue
		}
		i := strings.LastIndex(line, " ")
		if i < 0 {
			continue
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(line[i+1:]), 64); err == nil && v > 0 {
			return true
		}
	}
	return false
}

// TestLiveWiringDashboardIsOptional pins the tri-state on dashboard_addr. "off" and ""
// must both yield no server, and the difference matters because the dashboard has no
// auth: a dashboard built when the operator asked for none is an unauthenticated
// surface nobody knows is listening.
func TestLiveWiringDashboardIsOptional(t *testing.T) {
	for i, tc := range []struct {
		addr string
		want bool
	}{
		{"off", false},
		{"OFF", false}, // EqualFold: the check is case-insensitive on purpose
		{"", false},
		{":15010", true},
	} {
		t.Run(fmt.Sprintf("addr=%q", tc.addr), func(t *testing.T) {
			cfg := liveConfig(t, fmt.Sprintf("merlin_wiring_dash%d", i))
			cfg.Server.DashboardAddr = tc.addr

			built, err := BuildWithBackends(context.Background(), cfg)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			defer built.Close()

			if got := built.Dashboard != nil; got != tc.want {
				t.Fatalf("dashboard built = %v, want %v for dashboard_addr=%q", got, tc.want, tc.addr)
			}
			if !tc.want {
				return
			}
			rec := httptest.NewRecorder()
			built.Dashboard.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("dashboard GET / = %d, want 200 (its ingress probe expects 200 here, not the gate's 401)", rec.Code)
			}
		})
	}
}

// TestLiveWiringCleanupCancelsBackgroundWork covers the contract main() depends on:
// Servers.Close must stop the goroutines BuildWithBackends started (the promotion
// worker and the metrics sampler) and close the ClickHouse handles. If Close returned while the
// worker was still claiming jobs, a shutting-down pod would keep taking promotions it
// will never finish — which is exactly the abandoned-claim state §1's recovery sweep
// exists to clean up.
func TestLiveWiringCleanupCancelsBackgroundWork(t *testing.T) {
	built, err := BuildWithBackends(context.Background(), liveConfig(t, "merlin_wiring_cleanup"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	done := make(chan struct{})
	go func() { defer close(done); built.Close() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return within 10s — a closer is blocking process shutdown")
	}
}

// TestLiveWiringParentContextCancelStopsWorkers is the other half: the caller's
// context, not just Close, must stop background work. main() cancels on SIGTERM, and
// Kubernetes sends SIGTERM before the grace period expires, so a worker that ignores
// the parent context keeps claiming promotion jobs right up until SIGKILL.
func TestLiveWiringParentContextCancelStopsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	built, err := BuildWithBackends(ctx, liveConfig(t, "merlin_wiring_parentctx"))
	if err != nil {
		cancel()
		t.Fatalf("build: %v", err)
	}
	cancel() // SIGTERM equivalent

	done := make(chan struct{})
	go func() { defer close(done); built.Close() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked after the parent context was canceled")
	}
}

// TestLiveWiringScanCacheOpensAndClosesAgainstTheRealValkey builds with the scan cache
// ENABLED, which is the only path that dials the store. The hermetic tests cover the
// disabled default and the fail-fast; what only a real server can show is that the
// address the gate already uses for staging is usable for the cache too, and that the
// extra client is released on Close rather than leaking a connection per restart.
func TestLiveWiringScanCacheOpensAndClosesAgainstTheRealValkey(t *testing.T) {
	cfg := liveConfig(t, "merlin_wiring_scancache")
	cfg.Grype.ScanCache = config.ScanCacheConfig{Enabled: true, MaxDBAge: "24h"}

	// Asserted directly, because a buildScanCache that returned (nil, nil, nil) for an
	// enabled cache would pass every other test here: the build succeeds, Close works,
	// and reuse is simply never wired. That is the exact silent no-op the fail-fast
	// exists to prevent, so the non-nil store is the assertion.
	store, closeStore, err := buildScanCache(cfg)
	if err != nil {
		t.Fatalf("buildScanCache: %v", err)
	}
	if store == nil {
		t.Fatal("an enabled scan cache returned no store; reuse would be silently off")
	}
	if closeStore == nil {
		t.Error("an enabled scan cache returned no closer; its client would leak per restart")
	} else {
		closeStore()
	}

	built, err := BuildWithBackends(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build with the scan cache enabled: %v", err)
	}
	done := make(chan struct{})
	go func() { defer close(done); built.Close() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return within 10s — the scan cache client is blocking shutdown")
	}
}

// TestLiveWiringBackendFailuresAreNamed covers the fail() paths. Each one closes what
// was already opened and returns a wrapped error; the wrapping is the whole diagnostic
// surface for a pod that will not start, and an unwrapped error here means an operator
// reads a bare driver message with no indication of WHICH backend refused.
//
// These run last because each deliberately points one client at nothing.
func TestLiveWiringBackendFailuresAreNamed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{
			name:   "unparseable registry_token_ttl",
			mutate: func(c *config.Config) { c.Auth.RegistryTokenTTL = "five minutes" },
			want:   "registry_token_ttl",
		},
		{
			name:   "unparseable staging.session_ttl",
			mutate: func(c *config.Config) { c.Staging.SessionTTL = "one hour" },
			want:   "staging.session_ttl",
		},
		{
			name:   "unreachable valkey",
			mutate: func(c *config.Config) { c.Staging.ValkeyAddr = "127.0.0.1:1" },
			want:   "session store",
		},
		{
			name:   "unreachable clickhouse",
			mutate: func(c *config.Config) { c.Audit.ClickHouseDSN = "clickhouse://127.0.0.1:1/merlin" },
			want:   "audit writer",
		},
		{
			// An EMPTY JWKS URL is a config mistake rather than an outage, so unlike
			// an unreachable endpoint (see the tolerance test above) it must fail the
			// build. The tenant PREFIX must be in the message too: with several
			// tenants, an error naming only the failure tells an operator nothing
			// about which tenant's Entra config is wrong.
			name:   "missing JWKS URL",
			mutate: func(c *config.Config) { c.Tenants[0].Auth.JWKSURL = "" },
			want:   "tenant c3dev: JWKS keyfunc",
		},
		{
			name:   "unparseable grype memory limit",
			mutate: func(c *config.Config) { c.Grype.MemoryLimit = "two gigs" },
			want:   "grype.memory_limit",
		},
		{
			// Reaches buildScanCache rather than config.validate(): this Config was
			// built in code. An enabled cache with a window the policy cannot use must
			// stop the build, because the alternative is a pod that reports caching on
			// and reuses nothing.
			name: "unparseable scan cache window",
			mutate: func(c *config.Config) {
				c.Grype.ScanCache = config.ScanCacheConfig{Enabled: true, MaxDBAge: "one day"}
			},
			want: "scan cache",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := liveConfig(t, "merlin_wiring_errors")
			tc.mutate(&cfg)

			built, err := BuildWithBackends(context.Background(), cfg)
			if err == nil {
				if built.Close != nil {
					built.Close()
				}
				t.Fatal("expected a build failure")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %q so an operator knows which backend refused", err, tc.want)
			}
			// fail() must return nothing usable: a caller that ignores err and serves
			// main anyway would run a gate with a nil auditor.
			if built.Gate != nil || built.Metrics != nil || built.Dashboard != nil || built.Close != nil {
				t.Error("a failed build must return the zero Servers, so a caller cannot serve a half-wired gate")
			}
		})
	}
}
