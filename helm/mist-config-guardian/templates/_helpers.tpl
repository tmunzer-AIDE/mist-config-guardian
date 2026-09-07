{{- define "mist-config-guardian.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mist-config-guardian.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "mist-config-guardian.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mist-config-guardian.labels" -}}
app.kubernetes.io/name: {{ include "mist-config-guardian.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mist-config-guardian.secretName" -}}
{{- if .Values.secrets.create -}}
{{- printf "%s-secrets" (include "mist-config-guardian.fullname" .) -}}
{{- else -}}
{{- required "existingSecret is required when secrets.create is false" .Values.existingSecret -}}
{{- end -}}
{{- end }}
