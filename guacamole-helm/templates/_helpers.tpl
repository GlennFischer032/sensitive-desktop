{{- /* _helpers.tpl: define shared template helper macros here if needed */ -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "guacamole.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "guacamole.fullname" -}}
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
Common labels
*/}}
{{- define "guacamole.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "guacamole.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for Guacamole
*/}}
{{- define "guacamole.selectorLabels" -}}
app: guacamole
release: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for Desktop Manager API
*/}}
{{- define "desktop-api.selectorLabels" -}}
app: guacamole
component: desktop-api
release: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for Desktop Manager Frontend
*/}}
{{- define "desktop-frontend.selectorLabels" -}}
app: guacamole
component: desktop-frontend
release: {{ .Release.Name }}
{{- end }}

{{/*
Generate hostname for Guacamole
*/}}
{{- define "guacamole.hostname" -}}
{{- if .Values.guacamole.hostname | ne "" }}
{{- printf "%s-%s-%s.dyn.cloud.e-infra.cz" .Values.guacamole.hostname .Release.Name .Release.Namespace }}
{{- else }}
{{- printf "%s-%s.dyn.cloud.e-infra.cz" .Release.Name .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Generate hostname for Desktop Manager Frontend
*/}}
{{- define "desktop-frontend.hostname" -}}
{{- if .Values.desktopFrontend.hostname | ne "" }}
{{- printf "%s-%s-%s.dyn.cloud.e-infra.cz"  .Values.desktopFrontend.hostname .Release.Name .Release.Namespace }}
{{- else }}
{{- printf "%s-%s.dyn.cloud.e-infra.cz" .Release.Name .Release.Namespace }}
{{- end }}
{{- end }}
