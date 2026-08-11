# Merlin CI Integration — Image Scan & Publish

## Mental model

Merlin is a **drop-in Registry V2 endpoint** that sits in front of ACR. You do
not call a separate "scan API" — you `docker push` to Merlin exactly as you
would to a registry, and the gate runs **in-band**:

- **Pass** → manifest PUT returns `201`, image is forwarded to ACR.
- **Reject** → manifest PUT returns `400` with the reason in the body; image is
  **not** published.

So in CI, `docker push` *is* your scan-and-publish step. Its exit code is your
quality gate. No pipeline restructuring beyond repointing the registry host and
swapping the login credential.

## What changes in your existing pipeline

| Today (push straight to ACR)              | With Merlin                                   |
|-------------------------------------------|-----------------------------------------------|
| `docker login myacr.azurecr.io`           | `docker login c3devops.c3ci.cloud`            |
| `docker push myacr.azurecr.io/app:v1`     | `docker push c3devops.c3ci.cloud/app:v1`      |
| Publish always succeeds if creds valid    | Publish succeeds **only if scan passes**      |
| Separate scan job (Trivy/etc.), if any    | Scan is the push; delete the separate job     |

The host you push to (`<prefix>.<baseDomain>`) selects **which ACR** the image
lands in — `c3devops.c3ci.cloud` → `c3devops.azurecr.io`. One Merlin deployment
fronts many ACRs by DNS prefix.

## Authentication in CI (the key difference from local dev)

Local devs authenticate with an interactive `az login` token. **CI must use a
non-interactive service principal** via the OAuth2 client-credentials grant.
Merlin accepts it directly through `docker login`:

```bash
# Service principal with AcrPush intent, registered in the tenant's Entra app.
# username = client (app) ID, password = client secret.
echo "$ARM_CLIENT_SECRET" | docker login c3devops.c3ci.cloud \
  -u "$ARM_CLIENT_ID" --password-stdin
```

Under the hood the `docker` client hits `GET /token`; Merlin validates the
client-credentials against the tenant's Entra directory and mints a short-lived,
**prefix-bound** registry token that `/v2/` verifies. You never manage that
token yourself — `docker` handles the handshake.

> Two auth modes exist: (1) an Entra **user access token** as the password
> (interactive / `az`), and (2) **client-id + secret** (CI). CI wants mode 2 —
> no token acquisition step, no expiry juggling in your pipeline.

Store `ARM_CLIENT_ID` / `ARM_CLIENT_SECRET` as masked CI secrets. Nothing else
is needed.

## Minimal CI publish step

```bash
set -euo pipefail

HOST=c3devops.c3ci.cloud            # <prefix>.<baseDomain> — selects the target ACR
IMAGE="$HOST/app:${CI_COMMIT_SHA}"

docker build -t "$IMAGE" .
echo "$ARM_CLIENT_SECRET" | docker login "$HOST" -u "$ARM_CLIENT_ID" --password-stdin

# The gate runs here. Non-zero exit = rejected (or infra error). Fail the build.
docker push "$IMAGE"
```

That is the whole integration. `docker push` returns non-zero on a `400`
reject, which `set -e` turns into a failed job.

## Interpreting the outcome

The gate blocks on any of these conditions:

- **Trivy** — any `CRITICAL` CVE (LOW/MEDIUM/HIGH are reported but don't block).
- **Base-image policy** — image must derive from an allowed base (RHEL UBI /
  Chainguard / Wolfi).
- **Image age** — image must not exceed the configured age threshold (default 60 days).

| Status on manifest PUT   | Meaning                                                            | CI action                          |
|--------------------------|-------------------------------------------------------------------|------------------------------------|
| `201 Created`            | Passed, published to ACR                                          | Proceed                            |
| `400 Bad Request`        | **Rejected** — reason in body (`rejected: CVE-… (CRITICAL) …`)     | Fail the build; surface the reason |
| `401 Unauthorized`       | Bad/expired cred, or a token minted for another prefix used here  | Fix creds; re-`docker login`       |
| `404 Not Found`          | Unknown host prefix (no tenant configured)                        | Fix the registry host              |
| `503 + Retry-After`      | Scan pool saturated                                               | Retry after the header's seconds   |
| `500 / 502`              | Merlin/ACR infra error (not a policy decision)                    | Retry / alert ops                  |

Only `400` is a policy verdict. Treat `503` as retryable and `5xx` as infra —
don't confuse either with "image is vulnerable."

## Pulling the scan report into your pipeline

Every push (pass **or** reject) records the full Trivy findings. Two ways to get
them:

**A. From the response header** — the manifest PUT returns
`X-Merlin-Scan-Report-URL`. Capture it if you drive the push via raw HTTP.

**B. By image reference** (what you have in CI) — fetch a registry token, then
`GET /reports/<ref>`:

```bash
# Mint a pull-scoped registry token (same client-creds, prefix-bound to this host).
REG=$(curl -s -u "$ARM_CLIENT_ID:$ARM_CLIENT_SECRET" \
  "https://$HOST/token?service=merlin&scope=repository:app:pull" \
  | jq -r .token)

# Report addressable by repo:tag or repo@sha256 — JSON envelope {age, findings}.
curl -s -H "Authorization: Bearer $REG" \
  "https://$HOST/reports/app:${CI_COMMIT_SHA}" > trivy-report.json
```

The report is a JSON envelope:

```json
{
  "age": { "known": true, "created": "...", "age_days": 45, "threshold_days": 60, "compliant": true },
  "findings": [ {CVE, Severity, Pkg, Version, FixedVersion}, ... ],
  "infra_error": true,
  "error": "policy \"grype\" could not run: ..."
}
```

`infra_error`/`error` appear only when the gate did **not** complete for that push
(scan timeout, assemble or ACR failure) — empty findings then mean "not scanned",
not "clean". A reference with no recorded gate decision returns `404`; a report
that exists but cannot be read (audit store outage) returns `500` — retry.

To extract findings: `jq .findings[] < trivy-report.json`. To check age: `jq .age < trivy-report.json`.

Archive `trivy-report.json` as a build artifact so a `400` reject is explainable without
re-running anything. Use `app@sha256:<digest>` for an exact, unambiguous lookup.
Buildx pushes record the gate decision by digest; the tag on the pushed index is
recorded as an alias, so `repo:tag` lookups resolve for buildx pushes too.

## Notes for a clean refactor

- **Delete your standalone scan stage.** Merlin is the single enforcement point;
  a separate Trivy job duplicates work and can disagree with the gate.
- **buildx / multi-arch works** — Merlin forwards the image index and SLSA
  attestation verbatim; the index only commits once its gated image is in ACR,
  so a rejected image can't sneak through by reference.
- **Push clients cap the wait at 30 seconds.** Both `docker push` and
  `docker buildx build --push` hardcode a 30s `ResponseHeaderTimeout` that no flag
  or environment variable can raise, so Merlin must answer the manifest PUT within
  it. Merlin scans synchronously and publishes to ACR asynchronously to stay inside
  that budget; `gate_timeout` bounds the scan, not your client's patience. A scan
  that exceeds the budget fails the push as an infra error and is not published.
- **Large layers:** the deployment buffers blobs in memory, so very large layers
  (multi-GB) need pod memory headroom — a known limitation.
- **Per-environment routing:** point dev CI at `c3dev.c3ci.cloud`,
  prod-promotion CI at `c3prod.c3ci.cloud` — each maps to its own ACR with its
  own service principal. No code change, just the host and creds.
