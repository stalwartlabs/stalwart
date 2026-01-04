{{/*
Expand the name of the chart.
*/}}
{{- define "nats.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "nats.fullname" -}}
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
{{- define "nats.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Print the namespace
*/}}
{{- define "nats.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride }}
{{- end }}

{{/*
Print the namespace for the metadata section
*/}}
{{- define "nats.metadataNamespace" -}}
{{- with .Values.namespaceOverride }}
namespace: {{ . | quote }}
{{- end }}
{{- end }}

{{/*
Set default values.
*/}}
{{- define "nats.defaultValues" }}
{{- if not .defaultValuesSet }}
  {{- $name := include "nats.fullname" . }}
  {{- with .Values }}
    {{- $_ := set .config.jetstream.fileStore.pvc   "name" (.config.jetstream.fileStore.pvc.name   | default (printf "%s-js" $name)) }}
    {{- $_ := set .config.resolver.pvc              "name" (.config.resolver.pvc.name              | default (printf "%s-resolver" $name)) }}
    {{- $_ := set .config.websocket.ingress         "name" (.config.websocket.ingress.name         | default (printf "%s-ws" $name)) }}
    {{- $_ := set .configMap                        "name" (.configMap.name                        | default (printf "%s-config" $name)) }}
    {{- $_ := set .headlessService                  "name" (.headlessService.name                  | default (printf "%s-headless" $name)) }}
    {{- $_ := set .natsBox.contentsSecret           "name" (.natsBox.contentsSecret.name           | default (printf "%s-box-contents" $name)) }}
    {{- $_ := set .natsBox.contextsSecret           "name" (.natsBox.contextsSecret.name           | default (printf "%s-box-contexts" $name)) }}
    {{- $_ := set .natsBox.deployment               "name" (.natsBox.deployment.name               | default (printf "%s-box" $name)) }}
    {{- $_ := set .natsBox.serviceAccount           "name" (.natsBox.serviceAccount.name           | default (printf "%s-box" $name)) }}
    {{- $_ := set .podDisruptionBudget              "name" (.podDisruptionBudget.name              | default $name) }}
    {{- $_ := set .service                          "name" (.service.name                          | default $name) }}
    {{- $_ := set .serviceAccount                   "name" (.serviceAccount.name                   | default $name) }}
    {{- $_ := set .statefulSet                      "name" (.statefulSet.name                      | default $name) }}
    {{- $_ := set .promExporter.podMonitor          "name" (.promExporter.podMonitor.name          | default $name) }}
  {{- end }}

  {{- $values := get (include "tplYaml" (dict "doc" .Values "ctx" $) | fromJson) "doc" }}
  {{- $_ := set . "Values" $values }}

  {{- $hasContentsSecret := false }}
  {{- range $ctxKey, $ctxVal := .Values.natsBox.contexts }}
    {{- range $secretKey, $secretVal := dict "creds" "nats-creds" "nkey" "nats-nkeys" "tls" "nats-certs" }}
      {{- $secret := get $ctxVal $secretKey }}
      {{- if $secret }}
        {{- $_ := set $secret "dir" ($secret.dir | default (printf "/etc/%s/%s" $secretVal $ctxKey)) }}
        {{- if and (ne $secretKey "tls") $secret.contents }}
          {{- $hasContentsSecret = true }}
        {{- end }}
      {{- end }}
    {{- end }}
  {{- end }}
  {{- $_ := set $ "hasContentsSecret" $hasContentsSecret }}

  {{- with .Values.config }}
  {{- $config := include "nats.loadMergePatch" (merge (dict "file" "config/config.yaml" "ctx" $) .) | fromYaml }}
  {{- $_ := set $ "config" $config }}
  {{- end }}

  {{- $_ := set . "defaultValuesSet" true }}
{{- end }}
{{- end }}

{{/*
NATS labels
*/}}
{{- define "nats.labels" -}}
{{- with .Values.global.labels -}}
{{ toYaml . }}
{{ end -}}
helm.sh/chart: {{ include "nats.chart" . }}
{{ include "nats.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
NATS selector labels
*/}}
{{- define "nats.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nats.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: nats
{{- end }}

{{/*
NATS Box labels
*/}}
{{- define "natsBox.labels" -}}
{{- with .Values.global.labels -}}
{{ toYaml . }}
{{ end -}}
helm.sh/chart: {{ include "nats.chart" . }}
{{ include "natsBox.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
NATS Box selector labels
*/}}
{{- define "natsBox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nats.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: nats-box
{{- end }}

{{/*
Print the image
*/}}
{{- define "nats.image" }}
{{- $image := "" }}
{{- if .digest }}
{{- $image = printf "%s@%s" .repository .digest }}
{{- else }}
{{- $image = printf "%s:%s" .repository .tag }}
{{- end }}
{{- if or .registry .global.image.registry }}
{{- $image = printf "%s/%s" (.registry | default .global.image.registry) $image }}
{{- end }}
{{- if .fullImageName }}
{{- $image = .fullImageName }}
{{- end }}
image: {{ $image }}
{{- if or .pullPolicy .global.image.pullPolicy }}
imagePullPolicy: {{ .pullPolicy | default .global.image.pullPolicy }}
{{- end }}
{{- end }}

{{- define "nats.secretNames" -}}
{{- $secrets := list }}
{{- range $protocol := list "nats" "leafnodes" "websocket" "mqtt" "cluster" "gateway" }}
  {{- $configProtocol := get $.Values.config $protocol }}
  {{- if and (or (eq $protocol "nats") $configProtocol.enabled) $configProtocol.tls.enabled $configProtocol.tls.secretName }}
    {{- $secrets = append $secrets (merge (dict "name" (printf "%s-tls" $protocol)) $configProtocol.tls) }}
  {{- end }}
{{- end }}
{{- toJson (dict "secretNames" $secrets) }}
{{- end }}

{{- define "natsBox.secretNames" -}}
{{- $secrets := list }}
{{- range $ctxKey, $ctxVal := .Values.natsBox.contexts }}
{{- range $secretKey, $secretVal := dict "creds" "nats-creds" "nkey" "nats-nkeys" "tls" "nats-certs" }}
  {{- $secret := get $ctxVal $secretKey }}
    {{- if and $secret $secret.secretName }}
      {{- $secrets = append $secrets (merge (dict "name" (printf "ctx-%s-%s" $ctxKey $secretKey)) $secret) }}
    {{- end }}
  {{- end }}
{{- end }}
{{- toJson (dict "secretNames" $secrets) }}
{{- end }}

{{- define "nats.tlsCAVolume" -}}
{{- with .Values.tlsCA }}
{{- if and .enabled (or .configMapName .secretName) }}
- name: tls-ca
{{- if .configMapName }}
  configMap:
    name: {{ .configMapName | quote }}
{{- else if .secretName }}
  secret:
    secretName: {{ .secretName | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{- define "nats.tlsCAVolumeMount" -}}
{{- with .Values.tlsCA }}
{{- if and .enabled (or .configMapName .secretName) }}
- name: tls-ca
  mountPath: {{ .dir | quote }}
{{- end }}
{{- end }}
{{- end }}

{{/*
translates env var map to list
*/}}
{{- define "nats.env" -}}
{{- range $k, $v := . }}
{{- if kindIs "string" $v }}
- name: {{ $k | quote }}
  value: {{ $v | quote }}
{{- else if kindIs "map" $v }}
- {{ merge (dict "name" $k) $v | toYaml | nindent 2 }}
{{- else }}
{{- fail (cat "env var" $k "must be string or map, got" (kindOf $v)) }}
{{- end }}
{{- end }}
{{- end }}

{{- /*
nats.loadMergePatch
input: map with 4 keys:
- file: name of file to load
- ctx: context to pass to tpl
- merge: interface{} to merge
- patch: []interface{} valid JSON Patch document
output: JSON encoded map with 1 key:
- doc: interface{} patched json result
*/}}
{{- define "nats.loadMergePatch" -}}
{{- $doc := tpl (.ctx.Files.Get (printf "files/%s" .file)) .ctx | fromYaml | default dict -}}
{{- $doc = mergeOverwrite $doc (deepCopy (.merge | default dict)) -}}
{{- get (include "jsonpatch" (dict "doc" $doc "patch" (.patch | default list)) | fromJson ) "doc" | toYaml -}}
{{- end }}


{{- /*
nats.reloaderConfig
input: map with 2 keys:
- config: interface{} nats config
- dir: dir config file is in
output: YAML list of reloader config files
*/}}
{{- define "nats.reloaderConfig" -}}
  {{- $dir := trimSuffix "/" .dir -}}
  {{- with .config -}}
  {{- if kindIs "map" . -}}
    {{- range $k, $v := . -}}
      {{- if or (eq $k "cert_file") (eq $k "key_file") (eq $k "ca_file") }}
- -config
- {{ $v }}
      {{- else if hasSuffix "$include" $k }}
- -config
- {{ clean (printf "%s/%s" $dir $v) }}
      {{- else }}
        {{- include "nats.reloaderConfig" (dict "config" $v "dir" $dir) }}
      {{- end -}}
    {{- end -}}
  {{- end -}}
  {{- end -}}
{{- end -}}


{{- /*
nats.formatConfig
input: map[string]interface{}
output: string with following format rules
1. keys ending in $natsRaw are unquoted
2. keys ending in $natsInclude are converted to include directives
*/}}
{{- define "nats.formatConfig" -}}
  {{-
    (regexReplaceAll "\"<<\\s+(.*?)\\s+>>\""
      (regexReplaceAll "\".*\\$include\": \"(.*)\",?" (include "toPrettyRawJson" .) "include ${1};")
    "${1}")
  -}}
{{- end -}}
