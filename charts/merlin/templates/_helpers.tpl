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
{{- printf "%s-valkey:6379" (include "merlin.fullname" .) }}
{{- end }}
{{- end }}

{{/*
ClickHouse DSN helper.
If .Values.merlin.audit.clickhouseDSN is set, use it.
Otherwise, build from operator-CR defaults: clickhouse://<user>@clickhouse-<fullname>-ch:9000/merlin
NOTE: This DSN is the no-password form. The password is injected at runtime via environment
variable from the ESO secret (CLICKHOUSE_PASSWORD). The Merlin app must append the password
to the DSN when establishing the connection.
IMPORTANT: The operator Service name format must be confirmed in Phase 8; adjust if needed.
*/}}
{{- define "merlin.clickhouseDSN" -}}
{{- if .Values.merlin.audit.clickhouseDSN }}
{{- .Values.merlin.audit.clickhouseDSN }}
{{- else }}
{{- printf "clickhouse://%s@clickhouse-%s-ch:9000/merlin" .Values.clickhouse.user (include "merlin.fullname" .) }}
{{- end }}
{{- end }}
