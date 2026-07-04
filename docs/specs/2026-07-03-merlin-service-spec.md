# Merlin Service Spec

**Date:** 2026-07-03
**Status:** Behavior spec (authoritative reference for consumers)
**Related:**
- `2026-07-03-merlin-scan-publish-design.md` — how c3aiops CI integrates with Merlin.
- `2026-07-03-merlin-image-age-compliance-spec.md` — the image-age gate policy.

## 1. What Merlin is

Merlin is a **drop-in Registry V2 endpoint that sits in front of ACR** and runs a security
gate **in-band on the manifest PUT**. There is no separate "scan API": clients
`docker push` to Merlin exactly as to any registry, and the gate decides whether the image
is forwarded to the backing ACR.

- **Pass** → manifest PUT returns `201 Created`; image is forwarded to ACR.
- **Reject** → manifest PUT returns `400 Bad Request` with the reason in the body; image is
  NOT published.

Consequence: in CI, `docker push` *is* the scan-and-publish step, and its exit code is the
quality gate. No separate scan job, no pipeline restructuring beyond repointing the registry
host and swapping the login credential.

## 2. Host → ACR routing

- Clients push to `<prefix>.<baseDomain>` (e.g. `c3devops.c3ci.cloud`).
- The **prefix selects the backing ACR**: `c3devops.c3ci.cloud` → `c3devops.azurecr.io`.
- **One Merlin deployment fronts many ACRs** by DNS prefix.
- An unknown prefix (no tenant configured) → `404 Not Found`.
- Per-environment routing is expressed purely by host: dev CI → `c3dev.c3ci.cloud`,
  prod-promotion CI → `c3prod.c3ci.cloud`, each mapping to its own ACR with its own service
  principal. No client code change — only host + credential differ.

## 3. Registry V2 API surface

Merlin MUST implement the standard Docker Registry V2 (OCI distribution) protocol so that
unmodified `docker` / `buildx` clients work against it:

- `GET /v2/` — API version check; validates the bearer token minted by `/token`.
- `GET /token` — token endpoint for the docker login handshake (see §4).
- Blob upload endpoints (`POST/PATCH/PUT /v2/<repo>/blobs/uploads/…`) — buffer/forward layers.
- `PUT /v2/<repo>/manifests/<ref>` — **the gate.** Scan runs here; returns 201 or 400 (or the
  error codes in §6). On pass, the manifest is forwarded to the backing ACR.
- Manifest **lists / image indexes** (multi-arch) are supported — see §7.
- `GET /reports/<ref>` — Merlin-specific scan-report retrieval (see §5).

## 4. Authentication

Two auth modes, both exchanged through the standard `docker login` → `GET /token` handshake.
Merlin validates the credential against the tenant's Entra directory and mints a
**short-lived, prefix-bound registry token** that `/v2/` verifies. Clients never manage that
token themselves — `docker` performs the handshake.

### Mode 1 — Interactive (local dev)
- Username/password = an **Entra user access token** (e.g. from `az login` / `az acr login`
  flows). For humans at a workstation.

### Mode 2 — Service principal (CI) — REQUIRED for pipelines
- **OAuth2 client-credentials grant**: `username = client (app) ID`,
  `password = client secret`.
- The service principal must have **AcrPush intent**, registered in the tenant's Entra app.
- No token-acquisition step and no expiry juggling in the pipeline:
  ```bash
  echo "$MERLIN_CLIENT_SECRET" | docker login c3devops.c3ci.cloud \
    -u "$MERLIN_CLIENT_ID" --password-stdin
  ```

### Token scoping
- Minted registry tokens are **prefix-bound**. A token minted for one prefix used against
  another → `401 Unauthorized`.
- Pull-scoped tokens can be requested for report retrieval:
  `GET /token?service=merlin&scope=repository:<repo>:pull`.

## 5. Scan report

Every push — **pass or reject** — records the full Trivy findings. Two retrieval paths:

### A. Response header (raw-HTTP drivers)
- The manifest PUT returns `X-Merlin-Scan-Report-URL`. Available only when the client drives
  the push via raw HTTP (not via the docker CLI, which does not surface arbitrary headers).

### B. By image reference (the CI-friendly path)
```bash
REG=$(curl -s -u "$MERLIN_CLIENT_ID:$MERLIN_CLIENT_SECRET" \
  "https://$HOST/token?service=merlin&scope=repository:$REPO:pull" | jq -r .token)
curl -s -H "Authorization: Bearer $REG" \
  "https://$HOST/reports/$REPO@sha256:$DIGEST" > trivy-report.json
```
- Report is addressable by `repo:tag` OR `repo@sha256:<digest>`. **Prefer digest** for an
  exact, unambiguous lookup (buildx records by digest, not tag).
- Report is a JSON array of findings. Each finding:
  `{ CVE, Severity, Pkg, Version, FixedVersion }`.
- The report MUST also carry the **image-age policy result** (see age spec §3.4):
  `{ created, age_days, threshold_days, compliant }`.
- Consumers SHOULD archive `trivy-report.json` as a build artifact so a 400 reject is
  explainable without re-running.

## 6. Gate policy & status codes

The gate blocks on any of these policy conditions:
- **Trivy CVE** — any `CRITICAL` CVE blocks. `LOW`/`MEDIUM`/`HIGH` are reported but do NOT
  block.
- **Base-image policy** — image must derive from an allowed base (RHEL UBI / Chainguard /
  Wolfi).
- **Image-age policy** — image config `created` older than the configured threshold
  (default 60 days) blocks. Full behavior in the image-age compliance spec.

Multiple policy failures on one push SHOULD all be listed in the reject body.

| Status on manifest PUT | Meaning | Consumer action |
|------------------------|---------|-----------------|
| `201 Created` | Passed all policies, published to ACR | Proceed |
| `400 Bad Request` | **Policy verdict** — rejected; reason in body (e.g. `rejected: CVE-… (CRITICAL) …`, or age/base reason) | Fail the build; surface the reason |
| `401 Unauthorized` | Bad/expired credential, or a token minted for another prefix used here | Fix creds; re-`docker login` |
| `404 Not Found` | Unknown host prefix (no tenant configured) | Fix the registry host |
| `503` + `Retry-After` | Scan pool saturated | Retry after the header's seconds |
| `500` / `502` | Merlin/ACR infra error (NOT a policy decision) | Retry / alert ops |

**Critical distinction:** only `400` is a policy verdict. `503` is retryable; `5xx` is infra.
Neither `503` nor `5xx` means "image is vulnerable" — consumers MUST NOT conflate them.

## 7. Multi-arch / buildx

- `buildx` and multi-arch image indexes are supported.
- Merlin forwards the **image index and SLSA attestation verbatim**.
- The index only commits **once its gated image is in ACR**, so a rejected image cannot sneak
  through by reference.
- Age is evaluated per gated child manifest; effective age = oldest child (see age spec).

## 8. Performance, limits, timeouts

- The manifest PUT **waits on the scan** — tens of seconds to minutes depending on image
  size. Default gate timeout: **5 minutes**. Clients MUST set CI job / registry-client
  timeouts generously (≥ the gate timeout).
- **Known limitation:** the deployment **buffers blobs in memory**, so very large layers
  (multi-GB) require pod memory headroom. Size Merlin pods accordingly for large images.
- `503 + Retry-After` is the backpressure signal when the scan pool is saturated; clients
  SHOULD honor the header.

## 9. Consumer expectations (CI)

A compliant CI integration:
1. Repoints the registry host to `<prefix>.<baseDomain>` and logs in with a service
   principal (Mode 2).
2. Treats `docker push` as the scan gate — non-zero exit fails the build.
3. Distinguishes `400` (fail, surface reason) from `503` (retry after header) and `5xx`
   (infra retry/alert).
4. Deletes any standalone scan stage (Trivy/age) — Merlin is the single enforcement point;
   a separate job duplicates work and can disagree with the gate.
5. Fetches `/reports/<ref>` (by digest) and archives it as an artifact.
6. Sets a generous push/job timeout.

## 10. Non-goals / out of scope for this spec

- Merlin does not sweep external BOM manifests (`.c3release.yaml` / `values.yaml`); it gates
  only images pushed through it. Fleet-wide freshness views, if wanted, are separate.
- This spec documents observable behavior and the consumer contract; it does not prescribe
  Merlin's internal scan-pool implementation, storage, or ACR-forwarding mechanics beyond
  the guarantees stated above.
