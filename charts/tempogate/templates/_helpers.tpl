{{/*
Expand the name of the chart.
*/}}
{{- define "tempogate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "tempogate.fullname" -}}
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
{{- define "tempogate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "tempogate.labels" -}}
helm.sh/chart: {{ include "tempogate.chart" . }}
{{ include "tempogate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tempogate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tempogate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "tempogate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tempogate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the non-secret env ConfigMap.
*/}}
{{- define "tempogate.configMapName" -}}
{{- printf "%s-config" (include "tempogate.fullname" .) }}
{{- end }}

{{/*
PVC name for the SQLite state store: an operator-supplied existingClaim
when set, otherwise the chart-managed claim.
*/}}
{{- define "tempogate.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-state" (include "tempogate.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret-derived env entries plus user extraEnv. Shared verbatim by the
Deployment and the migrate Job so both see identical configuration. The
non-secret vars come from the ConfigMap via envFrom (see each workload).
*/}}
{{- define "tempogate.secretEnv" -}}
{{- with .Values.auth.upstream.google.clientIdSecretRef }}
{{- if .name }}
- name: OIDC_GOOGLE_CLIENT_ID
  valueFrom:
    secretKeyRef:
      name: {{ .name }}
      key: {{ required "auth.upstream.google.clientIdSecretRef.key is required when .name is set" .key }}
{{- end }}
{{- end }}
{{- with .Values.auth.upstream.google.clientSecretSecretRef }}
{{- if .name }}
- name: OIDC_GOOGLE_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .name }}
      key: {{ required "auth.upstream.google.clientSecretSecretRef.key is required when .name is set" .key }}
{{- end }}
{{- end }}
{{- with .Values.auth.clientSecretsSecretRef }}
{{- if .name }}
- name: OIDC_CLIENT_SECRETS
  valueFrom:
    secretKeyRef:
      name: {{ .name }}
      key: {{ required "auth.clientSecretsSecretRef.key is required when .name is set" .key }}
{{- end }}
{{- end }}
{{- with .Values.oidc.sessionSigningKeySecretRef }}
{{- if .name }}
- name: OIDC_SESSION_SIGNING_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .name }}
      key: {{ required "oidc.sessionSigningKeySecretRef.key is required when .name is set" .key }}
{{- end }}
{{- end }}
{{- with .Values.extraEnv }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}
