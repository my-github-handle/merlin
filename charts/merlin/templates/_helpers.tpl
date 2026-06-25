{{/*
Expand the name of the chart.
*/}}
{{- define "merlin.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "merlin.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "merlin.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "merlin.labels" -}}
helm.sh/chart: {{ include "merlin.chart" . }}
{{ include "merlin.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "merlin.selectorLabels" -}}
app.kubernetes.io/name: {{ include "merlin.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Valkey address helper.
If .Values.merlin.staging.valkeyAddr is set, use it.
Otherwise, default to the operator-CR generated service: <fullname>-valkey:6379
*/}}
{{- define "merlin.valkeyAddr" -}}
{{- if .Values.merlin.staging.valkeyAddr }}
{{- .Values.merlin.staging.valkeyAddr }}
{{- else }}
{{- printf "%s-valkey.%s.svc.cluster.local:6379" (include "merlin.fullname" .) .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
ClickHouse DSN helper.
If .Values.merlin.audit.clickhouseDSN is set, use it.
Otherwise, build from operator-CR defaults with ${CLICKHOUSE_PASSWORD} placeholder.
The literal ${CLICKHOUSE_PASSWORD} is NOT expanded by Helm — it stays in the rendered YAML.
At runtime, Merlin's config loader expands it from the CLICKHOUSE_PASSWORD env var
(injected by the Deployment from the ESO secret). This keeps the password out of the ConfigMap.
Service name: the Altinity operator creates `clickhouse-<chi-name>` (chi-name = <fullname>-ch);
we use the namespace-qualified FQDN so resolution does not depend on the pod's DNS search list
(verified live: the bare name is NXDOMAIN, the .svc.cluster.local FQDN resolves).
*/}}
{{- define "merlin.clickhouseDSN" -}}
{{- if .Values.merlin.audit.clickhouseDSN }}
{{- .Values.merlin.audit.clickhouseDSN }}
{{- else }}
{{- printf "clickhouse://%s:${CLICKHOUSE_PASSWORD}@clickhouse-%s-ch.%s.svc.cluster.local:9000/merlin" .Values.clickhouse.user (include "merlin.fullname" .) .Release.Namespace }}
{{- end }}
{{- end }}
