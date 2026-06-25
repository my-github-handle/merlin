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
report endpoint, keyed by the push ID:

```bash
# Get a registry token scoped to your repo (pull scope is enough for reports).
TOKEN=$(az account get-access-token --resource api://<merlin-audience> --query accessToken -o tsv)
REG=$(curl -s -u "00000000-0000-0000-0000-000000000000:$TOKEN" \
  "https://merlin.example.com/token?service=merlin&scope=repository:app:pull" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# Fetch the scan report (JSON array of findings).
curl -s -H "Authorization: Bearer $REG" \
  "https://merlin.example.com/reports/<push_id>"
```

The `<push_id>` is the last path segment of the `X-Merlin-Scan-Report-URL`
header returned on the manifest PUT. Example response:

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
