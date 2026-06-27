# Multi-ACR Tenant Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route each inbound `docker push` to a different ACR based on the DNS subdomain prefix the client connects to (e.g. `c3dev.c3ci.cloud` → `c3devacr.azurecr.io`), with per-prefix inbound Entra auth and per-prefix outbound workload-identity push.

**Architecture:** A new `internal/tenant` package owns all host→tenant logic. A `tenant.Resolver` maps an HTTP Host to a `Tenant{Prefix, Registry, Pusher, Authn}` built once at startup from a `tenants[]` config list. The Docker ingress `Handler` holds a `Resolver` (not single registry/pusher/authn values) and resolves the tenant at the top of each entry point. The registry token carries a `prefix` claim so a token minted on one host cannot be replayed against another. Gate policy, staging, audit, and the scan pool stay shared singletons.

**Tech Stack:** Go, `github.com/golang-jwt/jwt/v5`, `github.com/Azure/azure-sdk-for-go/sdk/azidentity`, `github.com/google/go-containerregistry`, Helm.

## Global Constraints

- gofmt/goimports clean; `go vet ./...` clean.
- Tests run with `go test -race ./...`; maintain 80%+ coverage.
- Errors wrapped with context via `fmt.Errorf("...: %w", err)`.
- No secrets in source; per-prefix `acr_client_id` and shared `registry_token_secret` come via `${ENV}` expansion (config loader already does strict `os.Expand`).
- Immutability: construct new values, do not mutate shared config structs after load.
- This is a HARD CUT: remove `acr.registry` and flat `auth.issuer/audience/jwks_url/tenant_id`. No backward-compat shim.
- Module path: `github.com/merlin-gate/merlin`.
- Unknown tenant → HTTP 404 (before auth). Cross-prefix token replay → HTTP 401.

---

### Task 1: Config schema — tenants list + ACR template

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: existing `Config`, `expandEnvStrict`, `applyDefaults`, `validate`.
- Produces:
  - `type TenantAuthConfig struct { Issuer, Audience, JWKSURL, TenantID string }` (yaml: `issuer`, `audience`, `jwks_url`, `tenant_id`)
  - `type TenantConfig struct { Prefix string; ACRClientID string; Auth TenantAuthConfig }` (yaml: `prefix`, `acr_client_id`, `auth`)
  - `ACRConfig` becomes `struct { RegistryTemplate string; BaseDomain string }` (yaml: `registry_template`, `base_domain`)
  - `Config` gains `Tenants []TenantConfig` (yaml: `tenants`)
  - `AuthConfig` keeps ONLY: `TenantID` REMOVED, `Issuer`/`Audience`/`JWKSURL` REMOVED; keeps `Service`, `RegistryTokenSecret`, `RegistryTokenTTL`.
  - `func (c TenantConfig) Registry(template string) string` — returns `strings.ReplaceAll(template, "{prefix}", c.Prefix)`.

- [ ] **Step 1: Write the failing tests**

Replace `TestLoadValidConfig` and the now-invalid `acr.registry`/`auth.issuer` tests. Add to `internal/config/config_test.go`:

```go
func TestLoadMultiTenantConfig(t *testing.T) {
	t.Setenv("DEV_CID", "dev-client-id")
	t.Setenv("PROD_CID", "prod-client-id")
	p := writeTemp(t, `
trivy:
  severity_threshold: CRITICAL
base_image:
  allowed_ids: [rhel]
acr:
  registry_template: "{prefix}acr.azurecr.io"
  base_domain: c3ci.cloud
tenants:
  - prefix: c3dev
    acr_client_id: ${DEV_CID}
    auth:
      issuer: https://login/dev/v2.0
      audience: api://merlin-dev
      jwks_url: https://login/dev/keys
      tenant_id: dev-tenant
  - prefix: c3prod
    acr_client_id: ${PROD_CID}
    auth:
      issuer: https://login/prod/v2.0
      audience: api://merlin-prod
      jwks_url: https://login/prod/keys
      tenant_id: prod-tenant
auth:
  registry_token_secret: shh
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Tenants) != 2 {
		t.Fatalf("tenants = %d, want 2", len(cfg.Tenants))
	}
	if got := cfg.Tenants[0].Registry(cfg.ACR.RegistryTemplate); got != "c3devacr.azurecr.io" {
		t.Errorf("registry = %q, want c3devacr.azurecr.io", got)
	}
	if cfg.Tenants[0].ACRClientID != "dev-client-id" {
		t.Errorf("client id not expanded: %q", cfg.Tenants[0].ACRClientID)
	}
}

func TestLoadRejectsDuplicatePrefix(t *testing.T) {
	p := writeTemp(t, `
base_image: { allowed_ids: [rhel] }
acr: { registry_template: "{prefix}acr.azurecr.io", base_domain: c3ci.cloud }
tenants:
  - { prefix: c3dev, acr_client_id: a, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
  - { prefix: c3dev, acr_client_id: b, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate prefix error, got %v", err)
	}
}

func TestLoadRejectsTemplateWithoutPlaceholder(t *testing.T) {
	p := writeTemp(t, `
base_image: { allowed_ids: [rhel] }
acr: { registry_template: "static.azurecr.io", base_domain: c3ci.cloud }
tenants:
  - { prefix: c3dev, acr_client_id: a, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "{prefix}") {
		t.Fatalf("expected template placeholder error, got %v", err)
	}
}

func TestLoadRejectsTenantMissingClientID(t *testing.T) {
	p := writeTemp(t, `
base_image: { allowed_ids: [rhel] }
acr: { registry_template: "{prefix}acr.azurecr.io", base_domain: c3ci.cloud }
tenants:
  - { prefix: c3dev, auth: { issuer: i, audience: a, jwks_url: j, tenant_id: t } }
auth: { registry_token_secret: shh }
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "acr_client_id") {
		t.Fatalf("expected acr_client_id error, got %v", err)
	}
}

func TestLoadRejectsEmptyTenants(t *testing.T) {
	p := writeTemp(t, `
base_image: { allowed_ids: [rhel] }
acr: { registry_template: "{prefix}acr.azurecr.io", base_domain: c3ci.cloud }
auth: { registry_token_secret: shh }
`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "at least one tenant") {
		t.Fatalf("expected empty tenants error, got %v", err)
	}
}
```

Delete `TestLoadValidConfig`, `TestLoadRejectsMissingACRRegistry`, `TestLoadRejectsMissingAuthIssuer`, `TestLoadRejectsMissingAuthAudience` (they assert removed fields). Keep `TestLoadAppliesThresholdDefault`, `TestLoadRejectsEmptyAllowedIDs`, `TestLoadRejectsInvalidThreshold`, the env-var tests, and the shutdown-timeout tests — but update any that set `acr.registry`/`auth.issuer` to use the new schema (replace those blocks with the `acr:`/`tenants:` shape shown above).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/... 2>&1 | head`
Expected: compile errors (unknown fields `RegistryTemplate`, `Tenants`, etc.) or FAIL.

- [ ] **Step 3: Implement the schema + validation**

In `internal/config/config.go`, replace the `ACRConfig` and `AuthConfig` structs and add tenant types:

```go
type ACRConfig struct {
	RegistryTemplate string `yaml:"registry_template"`
	BaseDomain       string `yaml:"base_domain"`
}

type TenantAuthConfig struct {
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	JWKSURL  string `yaml:"jwks_url"`
	TenantID string `yaml:"tenant_id"`
}

type TenantConfig struct {
	Prefix      string           `yaml:"prefix"`
	ACRClientID string           `yaml:"acr_client_id"`
	Auth        TenantAuthConfig `yaml:"auth"`
}

// Registry substitutes this tenant's prefix into the ACR host template.
func (t TenantConfig) Registry(template string) string {
	return strings.ReplaceAll(template, "{prefix}", t.Prefix)
}
```

Change `AuthConfig` to drop `Issuer`, `Audience`, `JWKSURL`, `TenantID` (keep `Service`, `RegistryTokenSecret`, `RegistryTokenTTL`). Add `Tenants []TenantConfig` with `yaml:"tenants"` to `Config`.

Replace the `validate()` ACR/auth checks (lines ~141-149) with:

```go
	if c.ACR.RegistryTemplate == "" {
		return fmt.Errorf("config: acr.registry_template is required")
	}
	if !strings.Contains(c.ACR.RegistryTemplate, "{prefix}") {
		return fmt.Errorf("config: acr.registry_template must contain {prefix}")
	}
	if c.ACR.BaseDomain == "" {
		return fmt.Errorf("config: acr.base_domain is required")
	}
	if len(c.Tenants) == 0 {
		return fmt.Errorf("config: at least one tenant is required")
	}
	seen := make(map[string]bool, len(c.Tenants))
	for i, t := range c.Tenants {
		if t.Prefix == "" {
			return fmt.Errorf("config: tenants[%d].prefix is required", i)
		}
		if seen[t.Prefix] {
			return fmt.Errorf("config: duplicate tenant prefix %q", t.Prefix)
		}
		seen[t.Prefix] = true
		if t.ACRClientID == "" {
			return fmt.Errorf("config: tenants[%d] (%s) acr_client_id is required", i, t.Prefix)
		}
		if t.Auth.Issuer == "" || t.Auth.Audience == "" || t.Auth.JWKSURL == "" || t.Auth.TenantID == "" {
			return fmt.Errorf("config: tenants[%d] (%s) auth block requires issuer, audience, jwks_url, tenant_id", i, t.Prefix)
		}
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/... -v 2>&1 | tail -20`
Expected: PASS for all listed tests.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/config/config.go internal/config/config_test.go
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): multi-tenant ACR schema (tenants[] + registry template); hard cut of single-registry fields"
```

---

### Task 2: ACR pusher with explicit workload-identity client ID

**Files:**
- Modify: `internal/acr/push.go`
- Test: `internal/acr/push_cred_test.go`

**Interfaces:**
- Consumes: existing `acrPusher`, `acrCredAuthenticator`.
- Produces: `func NewACRPusherWithClientID(registry, clientID string) (Pusher, error)` — builds an `acrPusher` whose `auth` is an `acrCredAuthenticator` backed by a `WorkloadIdentityCredential` for `clientID`. Errors if `registry` or `clientID` is empty.

Note: `acrCredAuthenticator.cred` is typed `*azidentity.DefaultAzureCredential`. Widen it to the `azcore.TokenCredential` interface so both default and workload-identity creds fit. Change the field to `cred azcore.TokenCredential` (import `github.com/Azure/azure-sdk-for-go/sdk/azcore`); `GetToken` is part of that interface, so `credential.go` needs no other change. `NewACRPusherWithCredential` keeps passing its `*DefaultAzureCredential` (it satisfies the interface).

- [ ] **Step 1: Write the failing test**

Add to `internal/acr/push_cred_test.go`:

```go
func TestNewACRPusherWithClientID_Validates(t *testing.T) {
	if _, err := NewACRPusherWithClientID("", "cid"); err == nil {
		t.Error("expected error for empty registry")
	}
	if _, err := NewACRPusherWithClientID("reg.azurecr.io", ""); err == nil {
		t.Error("expected error for empty client id")
	}
}

func TestNewACRPusherWithClientID_BuildsPusher(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "t")
	t.Setenv("AZURE_CLIENT_ID", "c")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/dev/null")
	t.Setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com/")
	p, err := NewACRPusherWithClientID("c3devacr.azurecr.io", "dev-client-id")
	if err != nil {
		t.Fatalf("build pusher: %v", err)
	}
	if p == nil {
		t.Fatal("nil pusher")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/acr/ -run NewACRPusherWithClientID -v 2>&1 | head`
Expected: compile error — `undefined: NewACRPusherWithClientID`.

- [ ] **Step 3: Implement the constructor**

In `internal/acr/push.go` add (after `NewACRPusherWithCredential`):

```go
// NewACRPusherWithClientID builds a Pusher authenticated by a specific Azure
// workload identity (federated, secretless), selected by clientID. Each tenant
// prefix maps to its own client ID so a dev push cannot reach a prod ACR.
func NewACRPusherWithClientID(registry, clientID string) (Pusher, error) {
	if registry == "" {
		return nil, fmt.Errorf("acr: registry is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("acr: client id is required")
	}
	cred, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		ClientID: clientID,
	})
	if err != nil {
		return nil, fmt.Errorf("acr workload identity credential (client %s): %w", clientID, err)
	}
	return &acrPusher{registry: registry, auth: &acrCredAuthenticator{registry: registry, cred: cred}}, nil
}
```

In `internal/acr/credential.go`: add `"github.com/Azure/azure-sdk-for-go/sdk/azcore"` import and change the field `cred *azidentity.DefaultAzureCredential` to `cred azcore.TokenCredential`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/acr/ -race 2>&1 | tail -10`
Expected: PASS (existing tests still green; new ones pass).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/acr/push.go internal/acr/credential.go internal/acr/push_cred_test.go
git add internal/acr/push.go internal/acr/credential.go internal/acr/push_cred_test.go
git commit -m "feat(acr): NewACRPusherWithClientID for per-prefix workload identity"
```

---

### Task 3: Registry token carries a prefix claim

**Files:**
- Modify: `internal/auth/registrytoken.go`
- Test: `internal/auth/registrytoken_test.go` (create if absent)

**Interfaces:**
- Consumes: existing `RegistryTokenIssuer`.
- Produces:
  - `Mint(subject, scope, prefix string) (string, int, error)` — adds `prefix` claim. (SIGNATURE CHANGE: third param.)
  - `Verify(token string) (subject, scope, prefix string, err error)` — returns the prefix claim. (SIGNATURE CHANGE: third return.)

This changes two callers (token endpoint mints; handler verifies) — both are updated in Task 5.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/registrytoken_test.go`:

```go
package auth

import (
	"testing"
	"time"
)

func TestRegistryTokenRoundTripsPrefix(t *testing.T) {
	iss := NewRegistryTokenIssuer([]byte("secret"), "merlin", time.Minute)
	tok, _, err := iss.Mint("user1", "repository:app:push,pull", "c3prod")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	sub, scope, prefix, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if sub != "user1" || scope != "repository:app:push,pull" || prefix != "c3prod" {
		t.Errorf("got sub=%q scope=%q prefix=%q", sub, scope, prefix)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run RoundTripsPrefix 2>&1 | head`
Expected: compile error — `Mint`/`Verify` arity mismatch.

- [ ] **Step 3: Implement the prefix claim**

In `internal/auth/registrytoken.go`:

```go
type registryClaims struct {
	Scope  string `json:"scope,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	jwt.RegisteredClaims
}

func (i *RegistryTokenIssuer) Mint(subject, scope, prefix string) (string, int, error) {
	now := time.Now()
	claims := registryClaims{
		Scope:  scope,
		Prefix: prefix,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "merlin",
			Subject:   subject,
			Audience:  jwt.ClaimStrings{i.service},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(i.secret)
	if err != nil {
		return "", 0, fmt.Errorf("sign registry token: %w", err)
	}
	return signed, int(i.ttl.Seconds()), nil
}

func (i *RegistryTokenIssuer) Verify(token string) (string, string, string, error) {
	var claims registryClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		return i.secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer("merlin"),
		jwt.WithAudience(i.service),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return "", "", "", fmt.Errorf("verify registry token: %w", err)
	}
	return claims.Subject, claims.Scope, claims.Prefix, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/ -run RoundTripsPrefix -v 2>&1 | tail`
Expected: PASS. (Other `internal/auth` tests may now fail to compile if they call Mint/Verify — fix those call sites in this step to the new arity, passing `""` for prefix where prefix is irrelevant.)

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/auth/registrytoken.go internal/auth/registrytoken_test.go
git add internal/auth/registrytoken.go internal/auth/registrytoken_test.go
git commit -m "feat(auth): registry token carries prefix claim to bind tenant"
```

---

### Task 4: `internal/tenant` package — Resolver + Tenant

**Files:**
- Create: `internal/tenant/tenant.go`
- Create: `internal/tenant/resolver.go`
- Test: `internal/tenant/resolver_test.go`

**Interfaces:**
- Consumes: `acr.Pusher`, `auth.Authenticator`.
- Produces:
  - `type Tenant struct { Prefix, Registry string; Pusher acr.Pusher; Authn auth.Authenticator }`
  - `type Resolver interface { ForHost(host string) (*Tenant, error) }`
  - `var ErrUnknownTenant = errors.New("tenant: unknown registry prefix")`
  - `func NewStaticResolver(baseDomain string, tenants map[string]*Tenant) Resolver` — `tenants` keyed by prefix.
  - `func PrefixFromHost(host, baseDomain string) string` — lowercases, strips `:port`, strips `.baseDomain` suffix, returns the remaining leading label (`""` if it does not match `<label>.<baseDomain>`).

- [ ] **Step 1: Write the failing test**

Create `internal/tenant/resolver_test.go`:

```go
package tenant

import (
	"errors"
	"testing"
)

func TestPrefixFromHost(t *testing.T) {
	cases := []struct{ host, base, want string }{
		{"c3dev.c3ci.cloud", "c3ci.cloud", "c3dev"},
		{"c3prod.c3ci.cloud:443", "c3ci.cloud", "c3prod"},
		{"C3DEV.C3CI.CLOUD", "c3ci.cloud", "c3dev"},
		{"c3ci.cloud", "c3ci.cloud", ""},             // bare base domain, no prefix
		{"evil.example.com", "c3ci.cloud", ""},        // wrong base domain
		{"a.b.c3ci.cloud", "c3ci.cloud", ""},          // multi-label prefix not allowed
	}
	for _, c := range cases {
		if got := PrefixFromHost(c.host, c.base); got != c.want {
			t.Errorf("PrefixFromHost(%q,%q) = %q, want %q", c.host, c.base, got, c.want)
		}
	}
}

func TestStaticResolverForHost(t *testing.T) {
	dev := &Tenant{Prefix: "c3dev", Registry: "c3devacr.azurecr.io"}
	r := NewStaticResolver("c3ci.cloud", map[string]*Tenant{"c3dev": dev})

	got, err := r.ForHost("c3dev.c3ci.cloud")
	if err != nil {
		t.Fatalf("ForHost: %v", err)
	}
	if got != dev {
		t.Errorf("got %+v, want dev tenant", got)
	}

	if _, err := r.ForHost("c3prod.c3ci.cloud"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("unknown prefix err = %v, want ErrUnknownTenant", err)
	}
	if _, err := r.ForHost("c3ci.cloud"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("bare base domain err = %v, want ErrUnknownTenant", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tenant/ 2>&1 | head`
Expected: compile error — package/types missing.

- [ ] **Step 3: Implement the package**

Create `internal/tenant/tenant.go`:

```go
// Package tenant maps an inbound request host to the ACR tenant that serves it.
package tenant

import (
	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/auth"
)

// Tenant bundles everything that was single-valued in the single-registry design:
// the resolved ACR host, its outbound push identity, and its inbound auth surface.
type Tenant struct {
	Prefix   string
	Registry string
	Pusher   acr.Pusher
	Authn    auth.Authenticator
}
```

Create `internal/tenant/resolver.go`:

```go
package tenant

import (
	"errors"
	"strings"
)

// ErrUnknownTenant is returned when a host's prefix matches no configured tenant.
var ErrUnknownTenant = errors.New("tenant: unknown registry prefix")

// Resolver maps a request host to its Tenant.
type Resolver interface {
	ForHost(host string) (*Tenant, error)
}

type staticResolver struct {
	baseDomain string
	byPrefix   map[string]*Tenant
}

// NewStaticResolver builds a Resolver from a prefix-keyed tenant map, fixed at startup.
func NewStaticResolver(baseDomain string, tenants map[string]*Tenant) Resolver {
	return &staticResolver{baseDomain: strings.ToLower(baseDomain), byPrefix: tenants}
}

func (s *staticResolver) ForHost(host string) (*Tenant, error) {
	prefix := PrefixFromHost(host, s.baseDomain)
	if prefix == "" {
		return nil, ErrUnknownTenant
	}
	t, ok := s.byPrefix[prefix]
	if !ok {
		return nil, ErrUnknownTenant
	}
	return t, nil
}

// PrefixFromHost extracts the single leading label of host relative to baseDomain.
// It lowercases, strips an optional ":port", and requires exactly "<label>.<baseDomain>".
// Returns "" when host is the bare base domain, has a different base, or has a
// multi-label prefix.
func PrefixFromHost(host, baseDomain string) string {
	host = strings.ToLower(host)
	if i := strings.IndexByte(host, ':'); i != -1 {
		host = host[:i]
	}
	suffix := "." + baseDomain
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return ""
	}
	return label
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -race -v 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/tenant/
git add internal/tenant/
git commit -m "feat(tenant): host->tenant Resolver with prefix extraction"
```

---

### Task 5: Wire the Handler to resolve tenants per request

**Files:**
- Modify: `internal/ingress/docker/handler.go`
- Modify: `internal/ingress/docker/manifest.go`
- Modify: `internal/ingress/docker/upload.go`
- Modify: `internal/ingress/docker/token.go`
- Test: `internal/ingress/docker/handler_test.go`, `internal/ingress/docker/tenant_routing_test.go` (create)

**Interfaces:**
- Consumes: `tenant.Resolver`, `tenant.Tenant`, `tenant.ErrUnknownTenant`, the new `Mint`/`Verify` arity (Task 3), per-tenant `Pusher`/`Authn` (Task 4).
- Produces:
  - `NewHandler(resolver tenant.Resolver, st *staging.Store, r *router.Router, o *Outcome, reports ReportSource) *Handler` — DROPS the `auth.Authenticator` and `registry string` params (now per-tenant via resolver). (SIGNATURE CHANGE.)
  - `TokenHandler` gains `Resolver tenant.Resolver` and uses the resolved tenant's `Authn` instead of a single `Authn`.
  - Handler stores `resolver tenant.Resolver`; removes fields `auth`, `registry`. `outcome.Pusher` is no longer used by manifest forwarding — the resolved tenant's `Pusher` is used instead.

Routing rules: every entry resolves the tenant from `r.Host`; `ErrUnknownTenant` → 404. `authenticate` verifies the registry token AND that its `prefix` claim equals the resolved tenant's `Prefix` (else challenge/401).

- [ ] **Step 1: Write the failing tests**

Create `internal/ingress/docker/tenant_routing_test.go`:

```go
package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/auth"
	"github.com/merlin-gate/merlin/internal/tenant"
)

// fakeResolver returns a fixed single tenant for the configured host prefix.
type fakeResolver struct{ t *tenant.Tenant }

func (f fakeResolver) ForHost(host string) (*tenant.Tenant, error) {
	if f.t != nil && host == f.t.Prefix+".c3ci.cloud" {
		return f.t, nil
	}
	return nil, tenant.ErrUnknownTenant
}

func TestUnknownHostReturns404(t *testing.T) {
	res := fakeResolver{t: &tenant.Tenant{Prefix: "c3dev", Registry: "c3devacr.azurecr.io", Authn: fakeAuth{ok: true}}}
	h := NewHandler(res, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "c3xxx.c3ci.cloud"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", rec.Code)
	}
}

func TestCrossPrefixTokenRejected(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	res := fakeResolver{t: &tenant.Tenant{Prefix: "c3prod", Registry: "c3prodacr.azurecr.io", Authn: fakeAuth{ok: true}}}
	h := NewHandler(res, nil, nil, nil, nil)
	h.SetRegistryAuth(iss, "https://merlin/token", "merlin")

	// Token minted for c3dev, presented to c3prod host.
	tok, _, _ := iss.Mint("u", "", "c3dev")
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "c3prod.c3ci.cloud"
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401 for cross-prefix token", rec.Code)
	}
}

func TestMatchingPrefixTokenAccepted(t *testing.T) {
	iss := auth.NewRegistryTokenIssuer([]byte("s"), "merlin", time.Minute)
	res := fakeResolver{t: &tenant.Tenant{Prefix: "c3prod", Registry: "c3prodacr.azurecr.io", Authn: fakeAuth{ok: true}}}
	h := NewHandler(res, nil, nil, nil, nil)
	h.SetRegistryAuth(iss, "https://merlin/token", "merlin")

	tok, _, _ := iss.Mint("u", "", "c3prod")
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "c3prod.c3ci.cloud"
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rec.Code)
	}
}

var _ = context.Background
```

Update `handler_test.go`: every `NewHandler(fakeAuth{...}, nil, nil, nil, "myreg.azurecr.io", nil)` becomes `NewHandler(fakeResolver{t: &tenant.Tenant{Prefix: "c3dev", Registry: "myreg.azurecr.io", Authn: fakeAuth{...}}}, nil, nil, nil, nil)` and each request sets `req.Host = "c3dev.c3ci.cloud"`. (The `fakeResolver` lives in `tenant_routing_test.go`, same package.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/ingress/docker/ 2>&1 | head`
Expected: compile errors (NewHandler arity; unknown `tenant`).

- [ ] **Step 3: Implement the Handler rewiring**

In `handler.go`:
- Replace fields `auth auth.Authenticator`, `registry string` with `resolver tenant.Resolver`. Add import `github.com/merlin-gate/merlin/internal/tenant`.
- New constructor:

```go
func NewHandler(resolver tenant.Resolver, st *staging.Store, r *router.Router, o *Outcome, reports ReportSource) *Handler {
	h := &Handler{resolver: resolver, store: st, router: r, outcome: o, reports: reports, mux: http.NewServeMux()}
	h.mux.HandleFunc("/v2/", h.route)
	h.mux.HandleFunc("/reports/", h.handleReport)
	return h
}
```

- In `route`, resolve the tenant first and 404 on unknown:

```go
func (h *Handler) route(w http.ResponseWriter, r *http.Request) {
	t, err := h.resolver.ForHost(r.Host)
	if err != nil {
		http.Error(w, "unknown registry", http.StatusNotFound)
		return
	}
	if !h.authenticate(w, r, t) {
		return
	}
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
		h.handleUpload(w, r, t)
	case strings.Contains(r.URL.Path, "/manifests/"):
		switch r.Method {
		case http.MethodPut:
			h.handleManifest(w, r, t)
		case http.MethodGet, http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, r)
	}
}
```

- `authenticate` takes the tenant and enforces the prefix claim:

```go
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, t *tenant.Tenant) bool {
	if h.regIssuer != nil {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		_, _, prefix, err := h.regIssuer.Verify(bearer)
		if err != nil || prefix != t.Prefix {
			h.challenge(w, r)
			return false
		}
		return true
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, err := t.Authn.Validate(r.Context(), bearer); err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="merlin",service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}
```

- `validatedIdentity` takes the tenant; in registry mode use `h.regIssuer.Verify` (ignoring prefix here — already enforced in `authenticate`), else `t.Authn.Validate`:

```go
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
```

In `outcome.go` — `Apply` must push to the request's tenant ACR, not a shared pusher:
- Remove the `Pusher acr.Pusher` field from `Outcome` (it was the single shared pusher).
- Change `Apply` signature to accept the pusher per request:
  `func (o *Outcome) Apply(ctx context.Context, pusher acr.Pusher, req router.GateRequest, res policy.Result, gateErr error) (Decision, error)` and use `pusher.Push(...)` at line 66 instead of `o.Pusher.Push(...)`.
- Update `outcome_test.go`/`outcome_audit_test.go` call sites to pass a fake pusher as the new 2nd arg.

In `manifest.go`:
- `handleManifest(w, r)` → `handleManifest(w http.ResponseWriter, r *http.Request, t *tenant.Tenant)`.
- Replace `h.registry` with `t.Registry`; replace `h.outcome.Pusher` with `t.Pusher` in `forwardManifest`/`seedAttestationBlobs`. Thread `t` into `forwardManifest` and `seedAttestationBlobs` (add `t *tenant.Tenant` param) and call `h.validatedIdentity(r, t)`.
- The gate-result push: change `h.outcome.Apply(ctx, req, res, gateErr)` → `h.outcome.Apply(ctx, t.Pusher, req, res, gateErr)`.
- `forwardManifest(w, ctx, repo, ref, raw, m, kind)` → add `t *tenant.Tenant`; inside use `t.Registry` and `t.Pusher`. Update the `kindIndex/kindAttestation` call site to pass `t`.

In `upload.go`:
- `handleUpload(w, r)` → `handleUpload(w http.ResponseWriter, r *http.Request, t *tenant.Tenant)`. (Upload uses `h.store` only; `t` is currently unused there but pass it for signature symmetry and future per-tenant staging — reference it via `_ = t` ONLY IF unused. Actually it IS unused: omit the param to avoid a lint error. Keep `handleUpload(w, r)` unchanged and call `h.handleUpload(w, r)` in route.)

  DECISION: upload does not need the tenant (staging is shared). Keep `handleUpload(w, r)` signature and call site `h.handleUpload(w, r)`.

In `token.go`:
- `TokenHandler` gains `Resolver tenant.Resolver`. `ServeHTTP` resolves the tenant from `r.Host` (404 on unknown), validates against the resolved tenant's `Authn` (and client creds), and mints with the tenant prefix:

```go
type TokenHandler struct {
	Resolver    tenant.Resolver
	ClientCreds auth.ClientCredentialsValidator
	Issuer      *auth.RegistryTokenIssuer
}

func (t *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ten, err := t.Resolver.ForHost(r.Host)
	if err != nil {
		http.Error(w, "unknown registry", http.StatusNotFound)
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || pass == "" {
		unauthorizedToken(w)
		return
	}
	scope := r.URL.Query().Get("scope")
	if id, err := ten.Authn.Validate(r.Context(), pass); err == nil {
		t.issue(w, id.Subject, scope, ten.Prefix)
		return
	}
	if id, err := t.ClientCreds.Validate(r.Context(), user, pass); err == nil {
		t.issue(w, id.Subject, scope, ten.Prefix)
		return
	}
	unauthorizedToken(w)
}

func (t *TokenHandler) issue(w http.ResponseWriter, subject, scope, prefix string) {
	tok, expiresIn, err := t.Issuer.Mint(subject, scope, prefix)
	if err != nil {
		http.Error(w, "token issuance failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token": tok, "access_token": tok, "expires_in": expiresIn,
	})
}
```

Remove the now-unused `Authn auth.Authenticator` field from `TokenHandler`. Update `token_test.go` to construct `TokenHandler{Resolver: fakeResolver{...}, ...}` and set `req.Host`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/ingress/docker/ -race 2>&1 | tail -25`
Expected: PASS. Fix any remaining call sites in `*_test.go` (integration tests construct `NewHandler`/`TokenHandler`) to the new signatures + `req.Host`.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/ingress/docker/
git add internal/ingress/docker/
git commit -m "feat(ingress): resolve ACR tenant per request by host; enforce prefix-bound token"
```

---

### Task 6: Build the resolver in `BuildWithBackends`

**Files:**
- Modify: `internal/app/app.go`
- Test: `internal/app/app_test.go` (extend existing validation tests)

**Interfaces:**
- Consumes: `config.Config` (Task 1 shape), `acr.NewACRPusherWithClientID` (Task 2), `auth.NewEntraKeyfunc`/`NewJWTAuthenticator`, `tenant.NewStaticResolver`/`Tenant`, new `NewHandler`/`TokenHandler` (Task 5).
- Produces: a `tenant.Resolver` injected into the Handler; per-tenant pusher + authn built in a loop.

- [ ] **Step 1: Write the failing test**

Add to `internal/app/app_test.go` (a validation-only test — no network, mirrors existing ones):

```go
func TestBuildWithBackendsRejectsNoTenants(t *testing.T) {
	cfg := minimalProdConfig() // helper already used by sibling tests; if absent, inline a Config with required prod fields set and Tenants empty
	cfg.Tenants = nil
	_, _, _, _, err := BuildWithBackends(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when no tenants configured")
	}
}
```

If `minimalProdConfig` does not exist, inline a `config.Config` literal setting `Auth.JWKSURL`-equivalent prod fields the function checks. NOTE: the JWKSURL/Issuer/Audience top-level checks at app.go:82-90 reference removed fields — Step 3 moves those into the per-tenant loop, so the validation test targets the tenant loop instead.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/app/ -run RejectsNoTenants 2>&1 | head`
Expected: compile error or FAIL.

- [ ] **Step 3: Implement the resolver wiring**

In `internal/app/app.go` `BuildWithBackends`:
- Delete the top-level `cfg.Auth.JWKSURL`/`Issuer`/`Audience` checks (lines ~82-90, removed fields).
- Keep checks for `RegistryTokenSecret`, `ExternalURL`, `Staging.*`, `Audit.ClickHouseDSN`. Replace the `ACR.Registry` check with `ACR.RegistryTemplate`/`BaseDomain` non-empty and `len(cfg.Tenants) > 0`.
- Replace the single `keyfunc`/`authn`/`pusher` construction with a per-tenant loop building a `map[string]*tenant.Tenant`:

```go
	tenants := make(map[string]*tenant.Tenant, len(cfg.Tenants))
	for _, tc := range cfg.Tenants {
		registry := tc.Registry(cfg.ACR.RegistryTemplate)
		kf, err := auth.NewEntraKeyfunc(bctx, tc.Auth.JWKSURL)
		if err != nil {
			return fail(fmt.Errorf("tenant %s: JWKS keyfunc: %w", tc.Prefix, err))
		}
		tAuthn := auth.NewJWTAuthenticator(tc.Auth.Issuer, tc.Auth.Audience, kf)
		tPusher, err := acr.NewACRPusherWithClientID(registry, tc.ACRClientID)
		if err != nil {
			return fail(fmt.Errorf("tenant %s: ACR pusher: %w", tc.Prefix, err))
		}
		tenants[tc.Prefix] = &tenant.Tenant{
			Prefix:   tc.Prefix,
			Registry: registry,
			Pusher:   tPusher,
			Authn:    tAuthn,
		}
	}
	resolver := tenant.NewStaticResolver(cfg.ACR.BaseDomain, tenants)
```

- The `Outcome` no longer holds a `Pusher` (removed in Task 5; `Apply` takes the tenant pusher per request). Build `Outcome{ReportBaseURL: "/reports", Recorder: auditor, IDGen: generatePushID}` — drop the `Pusher:` field. (Confirmed against `outcome.go`: `Apply` calls `o.Pusher.Push` for the gated-image push, so the pusher must be passed per request.)
- `handler := dockeringress.NewHandler(resolver, store, rt, outcome, reportsReader)`.
- `th := &dockeringress.TokenHandler{Resolver: resolver, ClientCreds: cc, Issuer: issuer}`.
- `cc := auth.NewEntraClientCredentials(cfg.Auth.TenantID, ...)` referenced a removed field — client-credentials tenant must now come from somewhere. DECISION: use the FIRST tenant's `Auth.TenantID` for the shared client-creds validator, or drop client-creds support in multi-tenant mode. Simplest correct choice: build client-creds per tenant is out of scope; for now construct `cc` from `cfg.Tenants[0].Auth.TenantID` and document the limitation in a code comment. (Revisit if per-tenant client-creds is needed.)
- `handler.SetRegistryAuth(issuer, cfg.Server.ExternalURL+"/token", cfg.Auth.Service)` unchanged.
- Update `Build` (hermetic) similarly: it builds a single fake tenant. Construct a one-entry resolver with `acr.NewACRPusher(<derived registry>)` and the stub authn, base domain from cfg. Keep it compiling and unit-testable.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/app/ ./... -race 2>&1 | grep -v "^ok\|no test files" | head -20`
Expected: no failures.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/app/app.go internal/app/app_test.go
git add internal/app/app.go internal/app/app_test.go
git commit -m "feat(app): build per-tenant resolver (pusher + authn) in BuildWithBackends"
```

---

### Task 7: Helm chart + values migration

**Files:**
- Modify: `charts/merlin/values.yaml`
- Modify: `charts/merlin/templates/configmap.yaml`
- Modify: `charts/merlin/templates/ingress.yaml`
- Modify: `charts/merlin/templates/deployment.yaml` (verify only)
- Modify on disk (gitignored, not committed): `values.smoke.yaml`, `values.opsadmin.yaml`, `values.prod.example.yaml`

**Interfaces:**
- Consumes: the config schema from Task 1.
- Produces: a rendered `config.yaml` matching the new schema, and an Ingress with one host per tenant prefix.

- [ ] **Step 1: Update values.yaml**

Replace the single-registry `merlin.acr`/`merlin.auth` issuer fields with:

```yaml
acr:
  registryTemplate: "{prefix}acr.azurecr.io"
  baseDomain: "c3ci.cloud"

tenants:
  - prefix: c3dev
    acrClientId: ""        # workload identity client ID (required)
    auth:
      issuer: ""
      audience: ""
      jwksUrl: ""
      tenantId: ""
  - prefix: c3prod
    acrClientId: ""
    auth:
      issuer: ""
      audience: ""
      jwksUrl: ""
      tenantId: ""
```

Keep `merlin.auth.registryTokenSecret`/`registryTokenTtl`/`service` (shared) and all shared sections.

- [ ] **Step 2: Update configmap.yaml**

Render the new config block. Replace the `acr:`/flat `auth:` issuer lines with:

```yaml
    acr:
      registry_template: {{ .Values.acr.registryTemplate | quote }}
      base_domain: {{ .Values.acr.baseDomain | quote }}
    tenants:
    {{- range .Values.tenants }}
      - prefix: {{ .prefix | quote }}
        acr_client_id: {{ .auth.acrClientId | default .acrClientId | quote }}
        auth:
          issuer: {{ .auth.issuer | quote }}
          audience: {{ .auth.audience | quote }}
          jwks_url: {{ .auth.jwksUrl | quote }}
          tenant_id: {{ .auth.tenantId | quote }}
    {{- end }}
    auth:
      registry_token_secret: ${REGISTRY_TOKEN_SECRET}
      registry_token_ttl: {{ .Values.merlin.auth.registryTokenTtl | default "5m" | quote }}
      service: {{ .Values.merlin.auth.service | default "merlin" | quote }}
```

(Match the existing indentation of the rendered config in this file; adjust `.Values` paths to the file's existing prefix, e.g. `.Values.merlin.acr` if that is the established convention. VERIFY against current configmap.yaml structure before editing.)

- [ ] **Step 3: Update ingress.yaml for multiple hosts**

Render one `host` rule per tenant, each `<prefix>.<baseDomain>`, all routing to the gate service:

```yaml
  rules:
  {{- range .Values.tenants }}
    - host: {{ printf "%s.%s" .prefix $.Values.acr.baseDomain | quote }}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: {{ include "merlin.fullname" $ }}
                port:
                  number: {{ $.Values.service.port | default 5000 }}
  {{- end }}
```

(Adapt to the existing ingress.yaml structure — TLS block, annotations, service name/port references. VERIFY current file first.)

- [ ] **Step 4: Render and verify**

Run:
```bash
helm template charts/merlin \
  --set acr.baseDomain=c3ci.cloud \
  --set 'tenants[0].prefix=c3dev' --set 'tenants[0].acrClientId=dev-cid' \
  --set 'tenants[0].auth.issuer=i' --set 'tenants[0].auth.audience=a' \
  --set 'tenants[0].auth.jwksUrl=j' --set 'tenants[0].auth.tenantId=t' \
  2>&1 | grep -A25 "kind: ConfigMap"
```
Expected: rendered config shows `registry_template`, `base_domain`, and a `tenants:` list with `c3dev`. Ingress shows `host: c3dev.c3ci.cloud`.

- [ ] **Step 5: Migrate on-disk values files + commit chart**

Update `values.smoke.yaml`, `values.opsadmin.yaml`, `values.prod.example.yaml` to the new schema on disk (smoke/opsadmin are gitignored; prod.example IS tracked).

```bash
git add charts/merlin/values.yaml charts/merlin/templates/configmap.yaml charts/merlin/templates/ingress.yaml charts/merlin/templates/deployment.yaml charts/merlin/values.prod.example.yaml
git commit -m "feat(chart): multi-tenant ACR config + per-prefix ingress hosts"
```

---

### Task 8: Full verification + docs

**Files:**
- Modify: `docs/USAGE.md`, `README.md` (if they document single-registry config)
- Modify: `docs/specs.md` (if it describes the config schema)

- [ ] **Step 1: Full test + vet + race**

Run:
```bash
go build ./... && go vet ./... && go test -race ./... 2>&1 | grep -v "^ok\|no test files"
```
Expected: empty output (all pass).

- [ ] **Step 2: Coverage check**

Run: `go test -cover ./internal/tenant/ ./internal/config/ ./internal/ingress/docker/ ./internal/acr/ ./internal/auth/ 2>&1 | tail`
Expected: each ≥ 80%. Add table cases if any is short.

- [ ] **Step 3: Update docs**

Update any single-registry config examples in `docs/USAGE.md`, `README.md`, `docs/specs.md` to the `tenants[]`/`registry_template` schema and explain host-prefix routing (`c3dev.c3ci.cloud` → `c3devacr.azurecr.io`). Document that unknown prefixes return 404 and tokens are prefix-bound.

- [ ] **Step 4: Commit**

```bash
git add docs/ README.md
git commit -m "docs: document multi-ACR tenant routing by DNS prefix"
```

---

## Self-Review

**Spec coverage:**
- Host subdomain prefix routing → Task 4 (`PrefixFromHost`/resolver), Task 5 (route).
- Template prefix→ACR → Task 1 (`Registry()`), Task 6 (loop).
- Per-prefix workload identity → Task 2, Task 6.
- Per-prefix inbound Entra auth → Task 4 (`Tenant.Authn`), Task 5 (token endpoint), Task 6 (per-tenant authn build).
- Shared policy/staging/audit → Task 6 (singletons unchanged).
- Hard cut → Task 1 (struct removal), Task 7 (chart).
- Prefix-bound token (no cross-tenant replay) → Task 3 (claim), Task 5 (enforce in `authenticate`).
- 404 unknown / 401 mismatch → Task 5 tests.
- Chart migration → Task 7.

**Resolved during planning (no longer open):**
- `Outcome.Apply` consumes a pusher (`o.Pusher.Push` at outcome.go:66) for the gated-image push → Task 5 removes `Outcome.Pusher` and passes `t.Pusher` into `Apply` per request.

**Open verification items flagged for the implementer (resolve during the task, not deferred):**
- Task 6: client-credentials validator tenant source (removed `cfg.Auth.TenantID`); use `cfg.Tenants[0].Auth.TenantID` with a documented comment.
- Task 7: exact `.Values` path prefix and ingress TLS/annotation structure — verify against current files.

**Type consistency:** `NewHandler` (5 args), `TokenHandler{Resolver,...}`, `Mint(subject,scope,prefix)`, `Verify→(sub,scope,prefix,err)`, `Tenant{Prefix,Registry,Pusher,Authn}`, `Resolver.ForHost`, `PrefixFromHost(host,baseDomain)`, `NewACRPusherWithClientID(registry,clientID)`, `TenantConfig.Registry(template)` — used consistently across tasks.

**Placeholder scan:** No TBD/TODO left as work; the three "verify during implementation" items are explicit investigation steps with a decided fallback, not vague instructions.
