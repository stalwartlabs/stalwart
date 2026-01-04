{{- /*
tplYaml
input: map with 2 keys:
- doc: interface{}
- ctx: context to pass to tpl function
output: JSON encoded map with 1 key:
- doc: interface{} with any keys called tpl or tplSpread values templated and replaced

maps matching the following syntax will be templated and parsed as YAML
{
  $tplYaml: string
}

maps matching the follow syntax will be templated, parsed as YAML, and spread into the parent map/slice
{
  $tplYamlSpread: string
}
*/}}
{{- define "tplYaml" -}}
  {{- $patch := get (include "tplYamlItr" (dict "ctx" .ctx "parentKind" "" "parentPath" "" "path" "/" "value" .doc) | fromJson) "patch" -}}
  {{- include "jsonpatch" (dict "doc" .doc "patch" $patch) -}}
{{- end -}}

{{- /*
tplYamlItr
input: map with 4 keys:
- path: string JSONPath to current element
- parentKind: string kind of parent element
- parentPath: string JSONPath to parent element
- value: interface{}
- ctx: context to pass to tpl function
output: JSON encoded map with 1 key:
- patch: list of patches to apply in order to template
*/}}
{{- define "tplYamlItr" -}}
  {{- $params := . -}}
  {{- $kind := kindOf $params.value -}}
  {{- $patch := list -}}
  {{- $joinPath := $params.path -}}
  {{- if eq $params.path "/" -}}
    {{- $joinPath = "" -}}
  {{- end -}}
  {{- $joinParentPath := $params.parentPath -}}
  {{- if eq $params.parentPath "/" -}}
    {{- $joinParentPath = "" -}}
  {{- end -}}

  {{- if eq $kind "slice" -}}
    {{- $iAdj := 0 -}}
    {{- range $i, $v := $params.value -}}
      {{- $iPath := printf "%s/%d" $joinPath (add $i $iAdj) -}}
      {{- $itrPatch := get (include "tplYamlItr" (dict "ctx" $params.ctx "parentKind" $kind "parentPath" $params.path "path" $iPath "value" $v) | fromJson) "patch" -}}
      {{- $itrLen := len $itrPatch -}}
      {{- if gt $itrLen 0 -}}
        {{- $patch = concat $patch $itrPatch -}}
        {{- if eq (get (index $itrPatch 0) "op") "remove" -}}
          {{- $iAdj = add $iAdj (sub $itrLen 2) -}}
        {{- end -}}
      {{- end -}}
    {{- end -}}

  {{- else if eq $kind "map" -}}
    {{- if and (eq (len $params.value) 1) (or (hasKey $params.value "$tplYaml") (hasKey $params.value "$tplYamlSpread")) -}}
      {{- $tpl := get $params.value "$tplYaml" -}}
      {{- $spread := false -}}
      {{- if hasKey $params.value "$tplYamlSpread" -}}
        {{- if eq $params.path "/" -}}
          {{- fail "cannot $tplYamlSpread on root object" -}}
        {{- end -}}
        {{- $tpl = get $params.value "$tplYamlSpread" -}}
        {{- $spread = true -}}
      {{- end -}}

      {{- $res := tpl $tpl $params.ctx -}}
      {{- $res = get (fromYaml (tpl "tpl: {{ nindent 2 .res }}" (merge (dict "res" $res) $params.ctx))) "tpl" -}}

      {{- if eq $spread false -}}
        {{- $patch = append $patch (dict "op" "replace" "path" $params.path "value" $res) -}}
      {{- else -}}
        {{- $resKind := kindOf $res -}}
        {{- if and (ne $resKind "invalid") (ne $resKind $params.parentKind) -}}
           {{- fail (cat "can only $tplYamlSpread slice onto a slice or map onto a map; attempted to spread" $resKind "on" $params.parentKind "at path" $params.path) -}}
        {{- end -}}
          {{- $patch = append $patch (dict "op" "remove" "path" $params.path) -}}
        {{- if eq $resKind "invalid" -}}
          {{- /* no-op */ -}}
        {{- else if eq $resKind "slice" -}}
          {{- range $v := reverse $res -}}
            {{- $patch = append $patch (dict "op" "add" "path" $params.path "value" $v) -}}
          {{- end -}}
        {{- else -}}
          {{- range $k, $v := $res -}}
            {{- $kPath := replace "~" "~0" $k -}}
            {{- $kPath = replace "/" "~1" $kPath -}}
            {{- $kPath = printf "%s/%s" $joinParentPath $kPath -}}
            {{- $patch = append $patch (dict "op" "add" "path" $kPath "value" $v) -}}
          {{- end -}}
        {{- end -}}
      {{- end -}}
    {{- else -}}
      {{- range $k, $v := $params.value -}}
        {{- $kPath := replace "~" "~0" $k -}}
        {{- $kPath = replace "/" "~1" $kPath -}}
        {{- $kPath = printf "%s/%s" $joinPath $kPath -}}
        {{- $itrPatch := get (include "tplYamlItr" (dict "ctx" $params.ctx "parentKind" $kind "parentPath" $params.path "path" $kPath "value" $v) | fromJson) "patch" -}}
        {{- if gt (len $itrPatch) 0 -}}
          {{- $patch = concat $patch $itrPatch -}}
        {{- end -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
  
  {{- toJson (dict "patch" $patch) -}}
{{- end -}}
