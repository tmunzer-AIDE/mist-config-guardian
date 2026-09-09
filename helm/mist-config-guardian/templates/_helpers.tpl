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

{{/*
The datastore settings that carry a credential.

These are assembled inside the pod rather than written to the ConfigMap. The
credential itself comes from the Secret, and Kubernetes expands $(VAR) in one
env entry from those defined before it, so the composed URI — password and all
— never exists at rest in a ConfigMap or in the rendered manifest. Expansion
only sees explicit `env` entries, never `envFrom`, which is why the credentials
are named here as well as arriving with the rest of the Secret.
*/}}
{{- define "mist-config-guardian.datastoreEnv" -}}
{{- if .Values.mongodb.enabled }}
- name: MONGODB_ROOT_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ include "mist-config-guardian.secretName" . }}
      key: MONGODB_ROOT_USERNAME
- name: MONGODB_ROOT_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "mist-config-guardian.secretName" . }}
      key: MONGODB_ROOT_PASSWORD
- name: MONGODB_URL
  value: "mongodb://$(MONGODB_ROOT_USERNAME):$(MONGODB_ROOT_PASSWORD)@{{ include "mist-config-guardian.fullname" . }}-mongodb:27017/?authSource=admin"
{{- end }}
{{- if .Values.redis.enabled }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "mist-config-guardian.secretName" . }}
      key: REDIS_PASSWORD
- name: REDIS_URL
  value: "redis://:$(REDIS_PASSWORD)@{{ include "mist-config-guardian.fullname" . }}-redis:6379/0"
- name: CELERY_BROKER_URL
  value: "redis://:$(REDIS_PASSWORD)@{{ include "mist-config-guardian.fullname" . }}-redis:6379/1"
- name: CELERY_RESULT_BACKEND
  value: "redis://:$(REDIS_PASSWORD)@{{ include "mist-config-guardian.fullname" . }}-redis:6379/2"
{{- end }}
{{- end }}

{{/* The pods that are allowed to open a connection to a datastore. */}}
{{- define "mist-config-guardian.datastoreClients" -}}
- podSelector:
    matchLabels:
      app.kubernetes.io/name: {{ include "mist-config-guardian.name" . }}
      app.kubernetes.io/instance: {{ .Release.Name }}
    matchExpressions:
      - key: app.kubernetes.io/component
        operator: In
        values: [api, worker, scheduler]
{{- end }}

{{/*
A digest of the Secret this release renders, for the pods that read it.

Rotating a credential is only half done when the Secret changes: the pods hold
their environment from the moment they started, so without this an upgrade
leaves every one of them using the old value. When the Secret is managed
elsewhere the chart cannot see its contents, this digest never changes, and
restarting the pods is the operator's step — the README says so.
*/}}
{{- define "mist-config-guardian.secretChecksum" -}}
{{- include (print $.Template.BasePath "/secret.yaml") . | sha256sum }}
{{- end }}
