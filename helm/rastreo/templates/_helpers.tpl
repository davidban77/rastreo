{{/*
Expand the name of the chart.
*/}}
{{- define "rastreo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "rastreo.fullname" -}}
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
{{- define "rastreo.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "rastreo.labels" -}}
helm.sh/chart: {{ include "rastreo.chart" . }}
{{ include "rastreo.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels used for matching pods to services and deployments.
*/}}
{{- define "rastreo.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rastreo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Container image reference with tag defaulting to appVersion.
*/}}
{{- define "rastreo.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
The sink config document, from sink.config or sink.configYaml. Empty when
neither is set. sink.configYaml is copied through untouched because Helm's YAML
parser strips a `!file` tag out of sink.config before any template runs, leaving
the path behind as a plain string the server would read as the credential.
*/}}
{{- define "rastreo.sinkConfig" -}}
{{- $sink := .Values.sink | default dict -}}
{{- if not (kindIs "map" $sink) -}}
{{- fail "sink is not a mapping. It holds the chart's sink keys — config, configYaml, probeIntervalSeconds, probeTimeoutSeconds — see the commented example in values.yaml." -}}
{{- end -}}
{{- $structured := $sink.config | default dict -}}
{{- $verbatim := $sink.configYaml | default "" -}}
{{- if not (kindIs "map" $structured) -}}
{{- fail "sink.config is not a mapping. It holds the sink document as YAML the chart renders into the ConfigMap; a document written as one string belongs in sink.configYaml." -}}
{{- end -}}
{{- if not (kindIs "string" $verbatim) -}}
{{- fail "sink.configYaml is not text. It holds the sink document as a verbatim string, written with a `|` block; a document the chart should render belongs in sink.config." -}}
{{- end -}}
{{- if and (gt (len $structured) 0) (gt (len (trim $verbatim)) 0) -}}
{{- fail "sink.config and sink.configYaml are both set: the chart writes one sink.yaml and will not merge them. Keep sink.config for a config Helm parses, or sink.configYaml for one it copies through verbatim (the only form that preserves a !file tag)." -}}
{{- end -}}
{{- if gt (len (trim $verbatim)) 0 -}}
{{- $verbatim | trimSuffix "\n" -}}
{{- else if gt (len $structured) 0 -}}
{{- toYaml $structured -}}
{{- end -}}
{{- end }}

{{/*
Structural check on a list of Kubernetes objects the chart splices into the pod
spec: a list, of mappings, each carrying the named fields as text. A value that
misses any of these reaches the templates as itself, and the range or the field
lookups over it fail with a Go template error naming nothing the user wrote.
*/}}
{{- define "rastreo.requireEntries" -}}
{{- $key := .key -}}
{{- if and .entries (not (kindIs "slice" .entries)) -}}
{{- fail (printf "%s is not a list. It holds one Kubernetes object per entry — see the commented example in values.yaml." $key) -}}
{{- end -}}
{{- range $i, $entry := .entries -}}
{{- if not (kindIs "map" $entry) -}}
{{- fail (printf "%s[%d] is not a mapping. Each entry is a Kubernetes object — see the commented example in values.yaml." $key $i) -}}
{{- end -}}
{{- range $field := $.required -}}
{{- $value := get $entry $field -}}
{{- if not $value -}}
{{- fail (printf "%s[%d] has no %s. Kubernetes requires one on every entry — see the commented example in values.yaml." $key $i $field) -}}
{{- end -}}
{{- if not (kindIs "string" $value) -}}
{{- fail (printf "%s[%d] does not give %s text. Kubernetes takes text there — quote a value YAML would otherwise read as a number or a boolean." $key $i $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
ServiceAccount name: explicit name wins; otherwise derive from fullname when
create is enabled, else fall back to the namespace default.
*/}}
{{- define "rastreo.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "rastreo.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
