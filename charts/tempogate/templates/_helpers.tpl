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
Reject values that would run more than one SQLite writer against the state
PVC. Included from the Deployment so every render evaluates it.
*/}}
{{- define "tempogate.validateValues" -}}
{{- if gt (int .Values.replicaCount) 1 }}
{{- fail (printf "replicaCount=%v is not supported: the SQLite state store allows exactly one writer, so replicaCount must be 0 or 1" .Values.replicaCount) }}
{{- end }}
{{- if .Values.autoscaling.enabled }}
{{- fail "autoscaling.enabled=true is not supported: the SQLite state store allows exactly one writer, so tempogate cannot be scaled horizontally" }}
{{- end }}
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
Secret-derived env entries for the Deployment. The migrate Job does not get
them: `tempogate migrate` needs only the state store, so it never sees secret
material. The non-secret vars come from the ConfigMap via envFrom, and user
extraEnv from tempogate.extraEnv; both reach the Deployment and the migrate
Job.
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
{{- if and .Values.service.admin.enabled (not .Values.admin.tokenSha256SecretRef.name) }}
{{- fail "service.admin.enabled requires admin.tokenSha256SecretRef: an exposed admin API without a token is locked and useless" }}
{{- end }}
{{- with .Values.admin.tokenSha256SecretRef }}
{{- if .name }}
- name: ADMIN_TOKEN_SHA256
  valueFrom:
    secretKeyRef:
      name: {{ .name }}
      key: {{ required "admin.tokenSha256SecretRef.key is required when .name is set" .key }}
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
{{- with .Values.keys.encryptionKeySecretRef }}
{{- if .name }}
- name: KEYS_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .name }}
      key: {{ required "keys.encryptionKeySecretRef.key is required when .name is set" .key }}
{{- end }}
{{- end }}
{{- end }}

{{/*
ADMIN_ALLOWED_HOSTS. Explicit admin.allowedHosts wins. With the admin Service
enabled, default to its DNS names on the Service port plus portless loopback
names (kubectl port-forward picks the local port), which a DNS-rebinding page
cannot present. Otherwise empty, leaving the binary's loopback default.
*/}}
{{- define "tempogate.adminAllowedHosts" -}}
{{- if .Values.admin.allowedHosts }}
{{- join "," .Values.admin.allowedHosts }}
{{- else if .Values.service.admin.enabled }}
{{- $svc := printf "%s-admin" (include "tempogate.fullname" .) }}
{{- $port := .Values.service.admin.port }}
{{- $ns := .Release.Namespace }}
{{- $hosts := list (printf "%s:%v" $svc $port) (printf "%s.%s:%v" $svc $ns $port) (printf "%s.%s.svc:%v" $svc $ns $port) (printf "%s.%s.svc.cluster.local:%v" $svc $ns $port) "127.0.0.1" "localhost" "[::1]" }}
{{- join "," $hosts }}
{{- end }}
{{- end }}

{{/*
User extraEnv, appended verbatim to the Deployment and the migrate Job.
*/}}
{{- define "tempogate.extraEnv" -}}
{{- with .Values.extraEnv }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}
