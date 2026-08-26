# Merlin Helm Chart

Helm chart for deploying Merlin, an image-publishing gate proxy that validates container images before forwarding them to per-tenant Azure Container Registries (ACR), routed by DNS subdomain prefix.

## Overview

Merlin acts as a gating layer in front of one or more ACRs, enforcing security policies on pushed images. Each push is routed to a per-tenant ACR by the host prefix: a client pushing to `<prefix>.<merlin.acr.baseDomain>` (e.g. `c3dev.c3ci.cloud`) is forwarded to the ACR derived from `merlin.acr.registryTemplate` with `{prefix}` substituted (e.g. `c3devacr.azurecr.io`). Each tenant has its own inbound Entra auth and its own outbound workload-identity client ID. Unknown prefixes return `404`, and a registry token minted on one tenant host is rejected (`401`) on another. The gate enforces:
- **Base image validation**: Ensures images are built on approved base images (Red Hat UBI, Wolfi, Chainguard)
- **Vulnerability scanning**: Scans images with Grype and rejects images with CRITICAL vulnerabilities
- **Audit logging**: Records all push attempts and gate decisions to ClickHouse
- **Entra (Azure AD) authentication**: Integrates with Azure Workload Identity for seamless ACR token acquisition

## Prerequisites

Before installing this chart, ensure the following are configured in your AKS cluster:

### 1. AKS Cluster with Workload Identity

AKS must have Workload Identity enabled, and the Merlin ServiceAccount must be federated with an Entra (Azure AD) application or managed identity that has:
- `AcrPull` and `AcrPush` roles on the target ACR
- Read access to the Azure Blob Storage container for staging

Configure the federation:
```bash
# Create managed identity (or use an existing Entra app)
az identity create --name merlin-identity --resource-group <rg> --location <region>

# Get the client ID
CLIENT_ID=$(az identity show --name merlin-identity --resource-group <rg> --query clientId -o tsv)

# Federate the identity with the Kubernetes ServiceAccount
az identity federated-credential create \
  --name merlin-sa-federation \
  --identity-name merlin-identity \
  --resource-group <rg> \
  --issuer <aks-oidc-issuer-url> \
  --subject system:serviceaccount:<namespace>:merlin
```

### 2. Kubernetes Operators (Pre-installed)

This chart requires the following Kubernetes operators to be installed cluster-wide. The chart emits Custom Resources (CRs) for these operators; it does NOT install the operators themselves.

#### a. Hyperspike Valkey Operator

Provisions the Valkey (Redis replacement) instance for staging metadata.

```bash
# Install Hyperspike Valkey operator
helm repo add hyperspike https://charts.hyperspike.io
helm repo update
helm install valkey-operator hyperspike/valkey-operator --namespace valkey-system --create-namespace
```

**API Version**: `hyperspike.io/v1` (Custom Resource: `Valkey`)

#### b. Altinity ClickHouse Operator

Provisions the ClickHouse cluster for audit logging.

```bash
# Install Altinity ClickHouse operator
kubectl apply -f https://raw.githubusercontent.com/Altinity/clickhouse-operator/master/deploy/operator/clickhouse-operator-install-bundle.yaml
```

**API Version**: `clickhouse.altinity.com/v1` (Custom Resource: `ClickHouseInstallation`)

#### c. External Secrets Operator (ESO)

Syncs secrets from Azure Key Vault (or other backends) into Kubernetes secrets.

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm install external-secrets external-secrets/external-secrets --namespace external-secrets-system --create-namespace
```

After installation, create a `ClusterSecretStore` for Azure Key Vault:
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: azure-keyvault-store
spec:
  provider:
    azurekv:
      authType: WorkloadIdentity
      vaultUrl: https://<your-keyvault>.vault.azure.net
      serviceAccountRef:
        name: external-secrets
        namespace: external-secrets-system
```

### 3. TLS Certificate

An Ingress resource with TLS requires a TLS secret containing the certificate for the Merlin hostname. Options:
- **Pre-created secret**: Create a TLS secret manually and reference it in `ingress.tlsSecretName`
- **cert-manager**: Use cert-manager to automatically provision certificates via an Ingress annotation:
  ```yaml
  ingress:
    annotations:
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
  ```

### 4. Azure Resources

Provision the following Azure resources before deployment:

- **Azure Container Registry (ACR)**: The upstream registry that approved images are forwarded to
- **Azure Blob Storage**: Container for staging image layers during push
- **Azure Key Vault** (if using ESO with Key Vault): Store the ClickHouse password
- **Entra App Registration or Managed Identity**: For Workload Identity federation (see step 1 above)

## Installation

### 1. Create a production values file

Copy the example values file and fill in the required placeholders:

```bash
cp charts/merlin/values.prod.example.yaml values.prod.yaml
```

Edit `values.prod.yaml` and replace all `<placeholder>` values with your actual configuration. See the [Required Values](#required-values) section below.

### 2. Install the chart

```bash
helm install merlin charts/merlin -f values.prod.yaml --namespace merlin --create-namespace
```

**Note**: There are NO Helm subchart dependencies. Valkey and ClickHouse are provisioned via operator Custom Resources, not Helm subcharts. Therefore, `helm dependency update` is NOT required.

### 3. Verify installation

```bash
# Check that all pods are running
kubectl get pods -n merlin

# Check that the Valkey and ClickHouse CRs were created
kubectl get valkey -n merlin
kubectl get clickhouseinstallations -n merlin

# Check that the ExternalSecret synced successfully
kubectl get externalsecrets -n merlin
kubectl get secret merlin-secrets -n merlin
```

## Required Values

The following values MUST be set in your production values file:

| Value | Description | Example |
|-------|-------------|---------|
| `image.repository` | ACR repository URL | `myacr.azurecr.io/merlin` |
| `image.tag` | Image tag (git SHA) | `abc1234` |
| `serviceAccount.workloadIdentityClientID` | Entra app/MI client ID | `12345678-1234-1234-1234-123456789abc` |
| `ingress.className` | Ingress controller class | `nginx` |
| `ingress.host` | Dashboard ingress host / fallback when `ingress.dashboardHost` is unset — NOT the registry push host (those are per-tenant: `<prefix>.<baseDomain>`) | `merlin-dashboard.example.com` |
| `ingress.tlsSecretName` | TLS secret name | `merlin-tls` |
| `externalSecrets.secretStoreRef.name` | ESO SecretStore name | `azure-keyvault-store` |
| `externalSecrets.data` | Secret mappings | `[{secretKey: clickhouse-password, remoteKey: merlin-ch-pass}]` |
| `merlin.acr.registryTemplate` | ACR host template (must contain `{prefix}`) | `{prefix}acr.azurecr.io` |
| `merlin.acr.baseDomain` | Base DNS domain; ingress exposes `<prefix>.<baseDomain>` per tenant | `c3ci.cloud` |
| `merlin.tenants[].prefix` | DNS subdomain prefix for this tenant | `c3dev` |
| `merlin.tenants[].acrClientId` | Workload-identity client ID with `AcrPush` on this tenant's ACR | `<client-id>` |
| `merlin.tenants[].auth.issuer` | Per-tenant Entra issuer | `https://sts.windows.net/<tenant-id>/` |
| `merlin.tenants[].auth.audience` | Per-tenant token audience | `<acr-client-id>` |
| `merlin.tenants[].auth.jwksUrl` | Per-tenant Entra JWKS URL | `https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys` |
| `merlin.tenants[].auth.tenantId` | Per-tenant Entra tenant ID | `<tenant-id>` |
| `merlin.staging.blobAccountURL` | Blob Storage account URL | `https://mystorageacct.blob.core.windows.net` |
| `merlin.staging.blobContainer` | Blob container name | `merlin-staging` |
| `valkey.storage.storageClassName` | StorageClass for Valkey | `managed-premium` or `""` (default) |
| `clickhouse.storage.storageClassName` | StorageClass for ClickHouse | `managed-premium` or `""` (default) |

## Configuration

### Ingress Annotations

For large docker image pushes, ensure the ingress controller allows unlimited body size:

```yaml
ingress:
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"  # Required for large layers
```

### Disabling Operators

If you want to use external Valkey or ClickHouse instances (not provisioned via operators), disable the operator CRs and provide external addresses:

```yaml
valkey:
  enabled: false
merlin:
  staging:
    valkeyAddr: "external-redis.example.com:6379"

clickhouse:
  enabled: false
merlin:
  audit:
    clickhouseDSN: "clickhouse://merlin:password@external-clickhouse.example.com:9000/merlin"
```

**Note**: If you disable the operators, ensure the external services are reachable from the cluster and credentials are configured.

### Scan reuse (`merlin.grype.scanCache`)

When the same manifest digest is pushed again, Merlin can serve the earlier Grype
report instead of re-scanning. On the opsadmin deployment 75.8% of scans in a day
(197 of 260) were re-scans of a digest already scanned, worth 104 minutes of Grype CPU.

```yaml
merlin:
  grype:
    scanCache:
      enabled: true
      maxDBAge: "24h"   # default; values above 48h are rejected at startup
```

It is **off by default**, and turning it on is a deliberate decision: it admits an
image on the strength of an earlier scan, which changes what a fail-closed gate does.
Reuse requires a Valkey — the same `merlin.staging.valkeyAddr` used for staging state
— and an enabled cache with no address fails at startup rather than starting up and
scanning everything.

`maxDBAge` bounds the **vulnerability database** behind a reused report, not the
entry's own age: a report stops being trustworthy when the CVE feed moves, not when
time passes. Anchore rebuilds the DB daily, so the 24h default means a report is
reused at most until its DB is superseded. A report whose DB build time is unknown is
never reused.

Reuse is safe against config changes because the **report** is cached, not the
verdict: `severityThreshold`, `enforce` and the image-age gate are re-applied to a
reused report on every push. A cache fault at request time costs a scan and nothing
else — the gate never fails because the cache is broken.

Verify with:

```promql
rate(merlin_scan_cache_total{result="hit"}[15m]) / rate(merlin_scan_cache_total[15m])
```

Note that `merlin_scan_duration_seconds_count` keeps climbing on hits: a reused report
still runs the gate and still records a (near-zero) duration. The counter above is the
direct evidence.

## Monitoring

Merlin exposes Prometheus metrics at `:9090/metrics` (cluster-internal). The metrics port is exposed via the Service but NOT via the Ingress.

**Nothing scrapes it until you say so.** With the Prometheus Operator, enable the chart's
`ServiceMonitor` (default off, because the manifest needs the `monitoring.coreos.com/v1`
CRDs and a cluster without them fails the whole release):

```yaml
metrics:
  serviceMonitor:
    enabled: true
    labels: {}       # must match the Prometheus CR's spec.serviceMonitorSelector
    interval: 30s
    scrapeTimeout: 10s
```

If that selector is non-empty and `labels` does not carry the label it expects, the
ServiceMonitor is created and silently never scraped. Two selectors have to accept you,
and an empty map `{}` means **all** for both — it is only an *absent*
`serviceMonitorNamespaceSelector` that restricts a Prometheus to its own namespace:

```bash
kubectl get prometheus -A -o \
  jsonpath='{range .items[*]}{.metadata.namespace}{" sm="}{.spec.serviceMonitorSelector}{" ns="}{.spec.serviceMonitorNamespaceSelector}{" replicas="}{.spec.replicas}{"\n"}{end}'
```

Check `replicas` in the same breath: a Prometheus scaled to 0 accepts your
ServiceMonitor on paper and scrapes nothing. The only proof is asking the running
instance for its targets:

```bash
kubectl get --raw "/api/v1/namespaces/<prom-ns>/pods/<prom-pod>:9090/proxy/api/v1/targets?state=active" \
  | grep -o '"job":"merlin"' | head
```

Without the operator, configure your Prometheus instance to scrape:

```yaml
- job_name: 'merlin'
  kubernetes_sd_configs:
    - role: service
      namespaces:
        names: [merlin]
  relabel_configs:
    - source_labels: [__meta_kubernetes_service_name]
      regex: merlin
      action: keep
    - source_labels: [__meta_kubernetes_service_port_name]
      regex: metrics
      action: keep
```

### Slack alerts

Scraped metrics tell you what happened once you look. The alerter tells you without
looking: every 15 minutes it runs three detectors over the audit table and posts what
is new to a Slack incoming webhook.

| Detector | Fires when |
|---|---|
| `novel_error` | An `error_detail` signature appears in the last hour that is absent from the last 7 days |
| `infra_error_rate` | The window's infra-error rate clears an absolute floor **and** is a multiple of the baseline rate |
| `killed_scan` | Enough grype scans were SIGKILLed (`signal: killed` / exit 137) in one window |

Only `infra_error` decisions are considered. A push rejected for a CRITICAL CVE is the
gate working, and alerting on those would bury every real finding.

**Off by default, and there is no `enabled` flag — the webhook is the switch.** The URL
is a credential, so it is never put in values; add it to the Secret that already holds
the ClickHouse password and reference it:

```yaml
merlin:
  alerts:
    slackWebhookFromSecret: true         # injects SLACK_WEBHOOK_URL from the Secret
    slackWebhookSecretKey: slack-webhook-url
    environment: merlin-opsadmin         # labels every message; defaults to the pod name
```

With `externalSecrets.enabled: true`, add `slack-webhook-url` to `externalSecrets.data`.
Otherwise patch the existing Secret directly. If the key is missing the pod fails at
startup rather than running an alerter that posts nowhere.

Optional tuning (all empty = the tuned defaults: `15m` / `1h` / `168h` / `6h`):

```yaml
merlin:
  alerts:
    interval: 15m
    recentWindow: 1h        # must be >= interval, or findings between runs are never seen
    baselineWindow: 168h    # keep inside audit retention, or old signatures read as novel
    cooldown: 6h            # per (detector, signature); a still-firing issue resurfaces after it
    killedScanThreshold: 5
    maxNovelPerRun: 5       # the remainder is logged, never dropped silently
```

Both window relationships are checked at startup and refuse to boot if wrong. Repeats
are suppressed via an `alert_notifications` table in the same ClickHouse database,
which deliberately has **no TTL** — expiring rows would re-announce every long-standing
finding.

Scope: `killed_scan` sees the grype **child** being killed. A SIGKILL to the merlin
**parent** (a pod OOMKill) writes no audit row at all, so no query can see it — use
`kube_pod_container_status_last_terminated_reason` for that.

## Dashboard

Merlin serves a built-in, read-only observability dashboard on `:8080` **by default**
(a single Overview page showing health hero, gated images table, and per-image scan reports). It
is exposed via the Service (cluster-internal), like the metrics port. Disable it by
setting `merlin.server.dashboardAddr: "off"` — the container/Service ports are then
omitted.

Reach it cluster-internally:

```bash
kubectl -n <ns> port-forward svc/merlin 8080:8080
# then open http://localhost:8080
```

To expose it externally, set `ingress.dashboardHost` to a **dedicated** host (it
serves `/`, which collides with the v2 push path on a shared host). The dashboard
has **no application-level auth** and reveals who pushed what plus your vulnerability
posture — only set `dashboardHost` behind an access-controlled ingress (internal-only,
IP allowlist, or an auth proxy). Leave it empty to keep the dashboard cluster-internal.

## Usage

After installation, developers push images through the tenant host they belong to.
Push to `<prefix>.<merlin.acr.baseDomain>`; Merlin routes to that tenant's ACR.

```bash
# 1. Authenticate with Azure
az login
# Log in to the tenant host (prefix c3dev, baseDomain c3ci.cloud)
docker login c3dev.c3ci.cloud

# 2. Push an image (gated by Merlin, forwarded to c3devacr.azurecr.io)
docker tag myimage:latest c3dev.c3ci.cloud/myrepo:mytag
docker push c3dev.c3ci.cloud/myrepo:mytag

# 3. Query the scan report (same tenant host)
PUSH_ID="<push-id>"
curl -H "Authorization: Bearer $(az account get-access-token --query accessToken -o tsv)" \
     https://c3dev.c3ci.cloud/reports/$PUSH_ID
```

Pushing to an unknown prefix returns `404`. A registry token obtained from one
tenant host cannot be used against another tenant host (`401`).

Merlin will:
1. Validate the base image (must be UBI, Wolfi, or Chainguard)
2. Scan for CRITICAL vulnerabilities with Grype
3. Reject images that fail the gate
4. Forward approved images to the tenant's ACR (`registryTemplate` with `{prefix}` substituted)

## Known Limitations

The following items are tracked as technical debt from Phase 6 and Phase 7 development:

### Phase 6 Punch-List Items

- **I-1: ACR token cache expiry**: ACR tokens are cached indefinitely in memory. No refresh mechanism implemented. Long-running Merlin instances may fail ACR pushes when tokens expire (typically after 3 hours). **Workaround**: Restart the Merlin pods periodically via a CronJob or external automation. **Fix**: Implement token refresh in `internal/upstream/acr/client.go`.

- **I-2: Staged-blob leak on 4xx**: If Merlin receives a 4xx error from ACR during `PUT /blobs/<digest>` finalization, the staged blob is left orphaned in Azure Blob Storage. **Impact**: Storage cost accumulation over time. **Workaround**: Periodic cleanup job to delete blobs older than N days from the staging container. **Fix**: Add cleanup logic in `internal/registry/staging/staging.go`.

- **I-3: Shared-blob cleanup under concurrent same-layer pushes**: Multiple pushes of the same layer concurrently can result in shared-blob cleanup races, leaving orphaned blobs. **Impact**: Minor storage cost. **Workaround**: Same as I-2 (periodic cleanup). **Fix**: Reference-counting or coordinator for shared blobs.

### Phase 7 Deployment Items

- **TCP probes until `/healthz` exists**: The Deployment uses TCP socket probes on port 5000 for liveness and readiness because Merlin does not yet implement a `/healthz` endpoint. The `/v2/` endpoint returns `401 Unauthorized` without a token, which fails HTTP 200 probes. **Fix**: Add a dedicated `/healthz` endpoint that returns `200 OK` and switch to HTTP probes.

- **ClickHouse networks/ip 0.0.0.0/0**: The ClickHouseInstallation CR specifies `ip: "0.0.0.0/0"` in the networks configuration, which is overly permissive. This is used as a placeholder until proper in-cluster network policies are defined. **Fix**: Restrict ClickHouse network access to the Merlin namespace or specific pod CIDR.

- **Grype vulnerability database download**: Grype requires a vulnerability database to perform scans. The Dockerfile bundles the `grype` binary, and the Deployment sets `GRYPE_DB_CACHE_DIR` to a writable `emptyDir` volume, but the pod needs internet egress to download the DB on first scan. **Options**:
  - Allow egress to `toolbox-data.anchore.io` for DB downloads
  - Pre-seed the cache by mounting a PersistentVolume with a pre-downloaded DB
  - Use a sidecar or init container to pre-populate the cache

## Troubleshooting

### Image Push Fails with "Unauthorized"

- Verify that your Entra token is valid: `az account get-access-token`
- Check that the Workload Identity federation is correctly configured
- Ensure the managed identity has `AcrPush` role on the target ACR

### Image Push Rejected

- Check the scan report via `/reports/<push-id>` to see the gate decision reason
- Common reasons:
  - Base image is not UBI, Wolfi, or Chainguard
  - Image contains CRITICAL vulnerabilities
- Fix the issue in your Dockerfile and rebuild

### Operator CRs Not Created

- Verify the operators are installed: `kubectl get crd | grep -E 'valkey|clickhouse|externalsecrets'`
- Check that the chart values have `valkey.enabled: true` and `clickhouse.enabled: true`
- Review the Helm release status: `helm status merlin -n merlin`

### Pod Stuck in Pending

- Check for PVC binding issues: `kubectl get pvc -n merlin`
- Verify that the specified `storageClassName` exists: `kubectl get storageclass`
- Check events: `kubectl describe pod <pod-name> -n merlin`

### Grype Scans Fail

- Ensure the pod has egress to download the Grype vulnerability database
- Check pod logs for Grype errors: `kubectl logs <pod-name> -n merlin | grep grype`
- Verify that `GRYPE_DB_CACHE_DIR` is writable (should be `/var/cache/grype` mounted as emptyDir)

## Upgrade

To upgrade an existing Merlin installation:

```bash
# Update your values file with new configuration
vim values.prod.yaml

# Upgrade the release
helm upgrade merlin charts/merlin -f values.prod.yaml --namespace merlin
```

## Uninstall

```bash
helm uninstall merlin --namespace merlin
```

**Note**: PersistentVolumeClaims for Valkey and ClickHouse are NOT automatically deleted. Delete them manually if you want to remove all data:

```bash
kubectl delete pvc -n merlin --all
```

## Contributing

Contributions are welcome! Please see the main repository README for guidelines.

## License

See the main repository LICENSE file.
