# Merlin Helm Chart

Helm chart for deploying Merlin, an image-publishing gate proxy that validates container images before forwarding them to Azure Container Registry (ACR).

## Overview

Merlin acts as a gating layer in front of ACR, enforcing security policies on pushed images:
- **Base image validation**: Ensures images are built on approved base images (Red Hat UBI, Wolfi, Chainguard)
- **Vulnerability scanning**: Scans images with Trivy and rejects images with CRITICAL vulnerabilities
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
| `ingress.host` | Merlin registry hostname | `merlin.example.com` |
| `ingress.tlsSecretName` | TLS secret name | `merlin-tls` |
| `externalSecrets.secretStoreRef.name` | ESO SecretStore name | `azure-keyvault-store` |
| `externalSecrets.data` | Secret mappings | `[{secretKey: clickhouse-password, remoteKey: merlin-ch-pass}]` |
| `merlin.acr.registry` | Upstream ACR URL | `myacr.azurecr.io` |
| `merlin.auth.issuer` | Entra tenant issuer | `https://sts.windows.net/<tenant-id>/` |
| `merlin.auth.audience` | Token audience | `<acr-client-id>` |
| `merlin.auth.jwksURL` | Entra JWKS URL | `https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys` |
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

## Monitoring

Merlin exposes Prometheus metrics at `:9090/metrics` (cluster-internal). The metrics port is exposed via the Service but NOT via the Ingress. Configure your Prometheus instance to scrape:

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

Alternatively, create a `ServiceMonitor` resource if you use the Prometheus Operator.

## Usage

After installation, developers can push images through Merlin:

```bash
# 1. Authenticate with Azure
az login
az acr login --name <your-acr-name>
docker login merlin.example.com

# 2. Push an image (gated by Merlin)
docker tag myimage:latest merlin.example.com/myrepo:mytag
docker push merlin.example.com/myrepo:mytag

# 3. Query the scan report
PUSH_ID="<push-id>"
curl -H "Authorization: Bearer $(az account get-access-token --query accessToken -o tsv)" \
     https://merlin.example.com/reports/$PUSH_ID
```

Merlin will:
1. Validate the base image (must be UBI, Wolfi, or Chainguard)
2. Scan for CRITICAL vulnerabilities with Trivy
3. Reject images that fail the gate
4. Forward approved images to the upstream ACR

## Known Limitations

The following items are tracked as technical debt from Phase 6 and Phase 7 development:

### Phase 6 Punch-List Items

- **I-1: ACR token cache expiry**: ACR tokens are cached indefinitely in memory. No refresh mechanism implemented. Long-running Merlin instances may fail ACR pushes when tokens expire (typically after 3 hours). **Workaround**: Restart the Merlin pods periodically via a CronJob or external automation. **Fix**: Implement token refresh in `internal/upstream/acr/client.go`.

- **I-2: Staged-blob leak on 4xx**: If Merlin receives a 4xx error from ACR during `PUT /blobs/<digest>` finalization, the staged blob is left orphaned in Azure Blob Storage. **Impact**: Storage cost accumulation over time. **Workaround**: Periodic cleanup job to delete blobs older than N days from the staging container. **Fix**: Add cleanup logic in `internal/registry/staging/staging.go`.

- **I-3: Shared-blob cleanup under concurrent same-layer pushes**: Multiple pushes of the same layer concurrently can result in shared-blob cleanup races, leaving orphaned blobs. **Impact**: Minor storage cost. **Workaround**: Same as I-2 (periodic cleanup). **Fix**: Reference-counting or coordinator for shared blobs.

### Phase 7 Deployment Items

- **TCP probes until `/healthz` exists**: The Deployment uses TCP socket probes on port 5000 for liveness and readiness because Merlin does not yet implement a `/healthz` endpoint. The `/v2/` endpoint returns `401 Unauthorized` without a token, which fails HTTP 200 probes. **Fix**: Add a dedicated `/healthz` endpoint that returns `200 OK` and switch to HTTP probes.

- **ClickHouse networks/ip 0.0.0.0/0**: The ClickHouseInstallation CR specifies `ip: "0.0.0.0/0"` in the networks configuration, which is overly permissive. This is used as a placeholder until proper in-cluster network policies are defined. **Fix**: Restrict ClickHouse network access to the Merlin namespace or specific pod CIDR.

- **Trivy vulnerability database download**: Trivy requires a vulnerability database to perform scans. The Dockerfile bundles the `trivy` binary, and the Deployment sets `TRIVY_CACHE_DIR` to a writable `emptyDir` volume, but the pod needs internet egress to download the DB on first scan. **Options**:
  - Allow egress to `ghcr.io` and `github.com` for DB downloads
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

### Trivy Scans Fail

- Ensure the pod has egress to download the Trivy vulnerability database
- Check pod logs for Trivy errors: `kubectl logs <pod-name> -n merlin | grep trivy`
- Verify that `TRIVY_CACHE_DIR` is writable (should be `/tmp/trivy-cache` mounted as emptyDir)

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
