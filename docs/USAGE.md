# Using Merlin

Merlin is a Docker Registry V2 proxy that scans every pushed image and only
publishes it to the backend registry (ACR) if it passes the gate:

- **Trivy** vulnerability scan — rejected if any `CRITICAL` finding.
- **Base-image** policy — must be built on RedHat UBI or Chainguard/Wolfi.

You push with the normal `docker` CLI; the gate runs in-band. A passing push
returns `201` and the image lands in ACR; a failing push fails with the reason.

> Replace `merlin.example.com` with your Merlin host and `app:v1` with your
> image. The token/audience below come from your deployment's Entra config.

## 1. Publish a Docker image

```bash
# 1. Authenticate (Entra ID). The username is ignored; the password is your token.
TOKEN=$(az account get-access-token --resource api://<merlin-audience> --query accessToken -o tsv)
echo "$TOKEN" | docker login merlin.example.com -u 00000000-0000-0000-0000-000000000000 --password-stdin

# 2. Tag your image for Merlin and push.
docker tag myimage:latest merlin.example.com/app:v1
docker push merlin.example.com/app:v1
```

**Pass** (exit 0):

```
v1: digest: sha256:<...> size: <...>
```

The image is now in ACR. Merlin also returns the scan summary in the
`X-Merlin-Scan-Report-URL` response header (see below).

**Reject** (non-zero exit) — the push fails with the reason, e.g.:

```
... manifests/v1: 400 Bad Request
rejected: 2 CRITICAL CVEs — CVE-2024-X (openssl), CVE-2024-Y (glibc)
```

or

```
rejected: base image not permitted: detected "alpine", allowed: rhel, wolfi, chainguard
```

A rejected image is **not** published.

## 2. Get the Trivy scan results

Every push (pass or fail) records the full Trivy report. Retrieve it from the
report endpoint, addressed by **the image reference you pushed** — no push ID needed:

```bash
# Get a registry token scoped to your repo (pull scope is enough for reports).
TOKEN=$(az account get-access-token --resource api://<merlin-audience> --query accessToken -o tsv)
REG=$(curl -s -u "00000000-0000-0000-0000-000000000000:$TOKEN" \
  "https://merlin.example.com/token?service=merlin&scope=repository:app:pull" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# Fetch the scan report by the tag you pushed (JSON array of findings).
curl -s -H "Authorization: Bearer $REG" \
  "https://merlin.example.com/reports/app:v1"
```

The report path accepts any of:

- **`app:v1`** — the `repo:tag` you pushed. If no exact tag match exists (e.g. a
  `docker buildx` push records the image by digest, not tag), it returns the most
  recent push for that repo.
- **`app@sha256:<digest>`** — exact, unambiguous lookup by manifest digest (the
  digest is shown in the `docker push` output).
- **`<push_id>`** — the opaque ID from the `X-Merlin-Scan-Report-URL` response
  header on the manifest PUT.

Example response:

```json
[
  {"CVE":"CVE-2026-5435","Severity":"MEDIUM","Pkg":"glibc","Version":"2.34-270.el9_8","FixedVersion":""},
  {"CVE":"CVE-2023-50495","Severity":"LOW","Pkg":"ncurses-libs","Version":"6.2-12...","FixedVersion":""}
]
```

Each finding has `CVE`, `Severity` (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), `Pkg`,
`Version`, and `FixedVersion` (empty when no fix is available yet).

> The gate only **blocks** on `CRITICAL`. LOW/MEDIUM/HIGH findings are reported
> in the scan result but do not stop the push.

## Observability Dashboard

Merlin ships a built-in, read-only dashboard. It is **on by default**, served on
`:8080` (override with `server.dashboard_addr`, or set it to `off` to disable). It
is served on its own port — keep that port network-restricted (it exposes who
pushed what and your vulnerability posture; there is no application-level auth in
this version).

The dashboard is a single **Overview** page displaying:
- **Health hero** — pass-rate gauge, push volume and scan latency percentiles, infrastructure health (ACR success rate, Trivy DB age).
- **Gated images table** — one row per image (repo:tag + pusher), verdict, severity counts (Critical/High/Medium/Low), and image age. Paginated 10 per page, newest first. Filter by repo, tag, or identity; toggle to show only CRITICAL images or rejected-only. Click any row to open its scan report. New decisions stream live via SSE.

Time range: **1d / 7d / 30d** (header toggle). Data is retained for
`audit.retention_days` days (default 30); wider ranges show only retained data.

### Image scan reports

Click any image in the feed/tables, or use the search box (type `repo:tag` or
`repo@sha256:…`) to open its scan report: verdict, provenance, severity counts, and
the full findings table (filter client-side by CVE / package / severity). "Export
JSON" returns the same findings as `GET /reports/<ref>`, pretty-printed. Reports
exist only for images Merlin has gated (pass or reject).

### Config

```yaml
server:
  dashboard_addr: ":8080"   # default :8080; set "off" to disable
audit:
  retention_days: 30        # audit + findings TTL
```
