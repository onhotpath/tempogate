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
Reject values the state driver cannot run: more than one SQLite writer
against the state PVC, or Postgres without a connection string. Included
from the Deployment so every render evaluates it.
*/}}
{{- define "tempogate.validateValues" -}}
{{- $driver := .Values.state.driver }}
{{- if eq $driver "sqlite" }}
{{- if gt (int .Values.replicaCount) 1 }}
{{- fail (printf "replicaCount=%v is not supported with state.driver=sqlite: SQLite allows exactly one writer, so replicaCount must be 0 or 1; set state.driver=postgres to run more replicas" .Values.replicaCount) }}
{{- end }}
{{- if .Values.autoscaling.enabled }}
{{- fail "autoscaling.enabled=true is not supported with state.driver=sqlite: SQLite allows exactly one writer; set state.driver=postgres to scale horizontally" }}
{{- end }}
{{- with .Values.updateStrategy.type }}
{{- if ne . "Recreate" }}
{{- fail (printf "updateStrategy.type=%s is not supported with state.driver=sqlite: two pods cannot write the state PVC at once, so only Recreate is accepted" .) }}
{{- end }}
{{- end }}
{{- else if eq $driver "postgres" }}
{{- if not .Values.state.postgres.dsnSecretRef.name }}
{{- fail "state.driver=postgres requires state.postgres.dsnSecretRef: the Secret holding the connection string" }}
{{- end }}
{{- if .Values.autoscaling.enabled }}
{{- if not (or .Values.autoscaling.targetCPUUtilizationPercentage .Values.autoscaling.targetMemoryUtilizationPercentage) }}
{{- fail "autoscaling.enabled=true requires autoscaling.targetCPUUtilizationPercentage or autoscaling.targetMemoryUtilizationPercentage" }}
{{- end }}
{{- end }}
{{- else }}
{{- fail (printf "state.driver must be \"sqlite\" or \"postgres\", got %q" $driver) }}
{{- end }}
{{- end }}

{{/*
Whether the state store is Postgres; otherwise it is SQLite on the PVC.
*/}}
{{- define "tempogate.postgres" -}}
{{- if eq .Values.state.driver "postgres" }}true{{- end }}
{{- end }}

{{/*
Where the Postgres connection string Secret is mounted, as a directory and
as the STATE_POSTGRES_DSN_FILE path.
*/}}
{{- define "tempogate.postgresDsnDir" -}}
/etc/tempogate/postgres
{{- end }}
{{- define "tempogate.postgresDsnFile" -}}
{{- include "tempogate.postgresDsnDir" . }}/dsn
{{- end }}

{{/*
Volume mounts of the serve container and the migrate initContainer: the
state store's (the SQLite PVC, or the Postgres DSN file) and the user's.
*/}}
{{- define "tempogate.volumeMounts" -}}
{{- if include "tempogate.postgres" . }}
- name: postgres-dsn
  mountPath: {{ include "tempogate.postgresDsnDir" . }}
  readOnly: true
{{- else }}
- name: state
  mountPath: {{ .Values.state.mountPath }}
{{- end }}
{{- with .Values.volumeMounts }}
{{ toYaml . }}
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
Secret-derived env entries for the serve container. The migrate
initContainer does not get them: `tempogate migrate` needs only the state
store, so its one secret is the Postgres DSN file (tempogate.volumeMounts)
when that driver is used. The non-secret vars come from the ConfigMap via
envFrom, and user extraEnv from tempogate.extraEnv; both reach the serve
container and the migrate initContainer.
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
{{- with .Values.state.postgres.listenDsnSecretRef }}
{{- if and .name (include "tempogate.postgres" $) }}
- name: STATE_POSTGRES_LISTEN_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .name }}
      key: {{ required "state.postgres.listenDsnSecretRef.key is required when .name is set" .key }}
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
User extraEnv, appended verbatim to the serve container and the migrate
initContainer.
*/}}
{{- define "tempogate.extraEnv" -}}
{{- with .Values.extraEnv }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}
