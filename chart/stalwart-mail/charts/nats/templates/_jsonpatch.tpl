{{- /*
jsonpatch
input: map with 2 keys:
- doc: interface{} valid JSON document
- patch: []interface{} valid JSON Patch document
output: JSON encoded map with 1 key:
- doc: interface{} patched json result
*/}}
{{- define "jsonpatch" -}}
  {{- $params := fromJson (toJson .) -}}
  {{- $patches := $params.patch -}}
  {{- $docContainer := pick $params "doc" -}}

  {{- range $patch := $patches -}}
    {{- if not (hasKey $patch "op") -}}
      {{- fail "patch is missing op key" -}}
    {{- end -}}
    {{- if and (ne $patch.op "add") (ne $patch.op "remove") (ne $patch.op "replace") (ne $patch.op "copy") (ne $patch.op "move") (ne $patch.op "test") -}}
      {{- fail (cat "patch has invalid op" $patch.op) -}}
    {{- end -}}
    {{- if not (hasKey $patch "path") -}}
      {{- fail "patch is missing path key" -}}
    {{- end -}}
    {{- if and (or (eq $patch.op "add") (eq $patch.op "replace") (eq $patch.op "test")) (not (hasKey $patch "value")) -}}
      {{- fail (cat "patch with op" $patch.op "is missing value key") -}}
    {{- end -}}
    {{- if and (or (eq $patch.op "copy") (eq $patch.op "move")) (not (hasKey $patch "from")) -}}
      {{- fail (cat "patch with op" $patch.op "is missing from key") -}}
    {{- end -}}

    {{- $opPathKeys := list "path" -}}
    {{- if or (eq $patch.op "copy") (eq $patch.op "move") -}}
      {{- $opPathKeys = append $opPathKeys "from" -}}
    {{- end -}}
    {{- $reSlice := list -}}

    {{- range $opPathKey := $opPathKeys -}}
      {{- $obj := $docContainer -}}
      {{- if and (eq $patch.op "copy") (eq $opPathKey "from") -}}
        {{- $obj = (fromJson (toJson $docContainer)) -}}
      {{- end -}}
      {{- $key := "doc" -}}
      {{- $lastMap := dict "root" $obj -}}
      {{- $lastKey := "root" -}}
      {{- $paths := (splitList "/" (get $patch $opPathKey)) -}}
      {{- $firstPath := index $paths 0 -}}
      {{- if ne (index $paths 0) "" -}}
        {{- fail (cat "invalid" $opPathKey (get $patch $opPathKey) "must be empty string or start with /") -}}
      {{- end -}}
      {{- $paths = slice $paths 1 -}}

      {{- range $path := $paths -}}
        {{- $path = replace "~1" "/" $path -}}
        {{- $path = replace "~0" "~" $path -}}

        {{- if kindIs "slice" $obj -}}
          {{- $mapObj := dict -}}
          {{- range $i, $v := $obj -}}
            {{- $_ := set $mapObj (toString $i) $v -}}
          {{- end -}}
          {{- $obj = $mapObj -}}
          {{- $_ := set $lastMap $lastKey $obj -}}
          {{- $reSlice = prepend $reSlice (dict "lastMap" $lastMap "lastKey" $lastKey "mapObj" $obj) -}}
        {{- end -}}

        {{- if kindIs "map" $obj -}}
          {{- if not (hasKey $obj $key) -}}
            {{- fail (cat "key" $key "does not exist") -}}
          {{- end -}}
          {{- $lastKey = $key -}}
          {{- $lastMap = $obj -}}
          {{- $obj = index $obj $key -}}
          {{- $key = $path -}}
        {{- else -}}
          {{- fail (cat "cannot iterate into path" $key "on type" (kindOf $obj)) -}}
        {{- end -}}
      {{- end -}}

      {{- $_ := set $patch (printf "%sKey" $opPathKey) $key -}}
      {{- $_ := set $patch (printf "%sLastKey" $opPathKey) $lastKey -}}
      {{- $_ = set $patch (printf "%sLastMap" $opPathKey) $lastMap -}}
    {{- end -}}

    {{- if eq $patch.op "move" }}
      {{- if and (ne $patch.path $patch.from) (hasPrefix (printf "%s/" $patch.path) (printf "%s/" $patch.from)) -}}
        {{- fail (cat "from" $patch.from "may not be a child of path" $patch.path) -}}
      {{- end -}}
    {{- end -}}

    {{- if or (eq $patch.op "move") (eq $patch.op "copy") (eq $patch.op "test") }}
      {{- $key := $patch.fromKey -}}
      {{- $lastMap := $patch.fromLastMap -}}
      {{- $lastKey := $patch.fromLastKey -}}
      {{- $setKey := "value" -}}
      {{- if eq $patch.op "test" }}
        {{- $key = $patch.pathKey -}}
        {{- $lastMap = $patch.pathLastMap -}}
        {{- $lastKey = $patch.pathLastKey -}}
        {{- $setKey = "testValue" -}}
      {{- end -}}
      {{- $obj := index $lastMap $lastKey -}}

      {{- if kindIs "map" $obj -}}
        {{- if not (hasKey $obj $key) -}}
          {{- fail (cat $key "does not exist") -}}
        {{- end -}}
        {{- $_ := set $patch $setKey (index $obj $key) -}}

      {{- else if kindIs "slice" $obj -}}
        {{- $i := atoi $key -}}
        {{- if ne $key (toString $i) -}}
          {{- fail (cat "cannot convert" $key "to int") -}}
        {{- end -}}
        {{- if lt $i 0 -}}
          {{- fail "slice index <0" -}}
        {{- else if lt $i (len $obj) -}}
          {{- $_ := set $patch $setKey (index $obj $i) -}}
        {{- else -}}
          {{- fail "slice index >= slice length" -}}
        {{- end -}}

      {{- else -}}
        {{- fail (cat "cannot" $patch.op $key "on type" (kindOf $obj)) -}}
      {{- end -}}
    {{- end -}}

    {{- if or (eq $patch.op "remove") (eq $patch.op "replace") (eq $patch.op "move") }}
      {{- $key := $patch.pathKey -}}
      {{- $lastMap := $patch.pathLastMap -}}
      {{- $lastKey := $patch.pathLastKey -}}
      {{- if eq $patch.op "move" }}
        {{- $key = $patch.fromKey -}}
        {{- $lastMap = $patch.fromLastMap -}}
        {{- $lastKey = $patch.fromLastKey -}}
      {{- end -}}
      {{- $obj := index $lastMap $lastKey -}}

      {{- if kindIs "map" $obj -}}
        {{- if not (hasKey $obj $key) -}}
          {{- fail (cat $key "does not exist") -}}
        {{- end -}}
        {{- $_ := unset $obj $key -}}

      {{- else if kindIs "slice" $obj -}}
        {{- $i := atoi $key -}}
        {{- if ne $key (toString $i) -}}
          {{- fail (cat "cannot convert" $key "to int") -}}
        {{- end -}}
        {{- if lt $i 0 -}}
          {{- fail "slice index <0" -}}
        {{- else if eq $i 0 -}}
          {{- $_ := set $lastMap $lastKey (slice $obj 1) -}}
        {{- else if lt $i (sub (len $obj) 1) -}}
          {{- $_ := set $lastMap $lastKey (concat (slice $obj 0 $i) (slice $obj (add $i 1) (len $obj))) -}}
        {{- else if eq $i (sub (len $obj) 1) -}}
          {{- $_ := set $lastMap $lastKey (slice $obj 0 (sub (len $obj) 1)) -}}
        {{- else -}}
          {{- fail "slice index >= slice length" -}}
        {{- end -}}

      {{- else -}}
        {{- fail (cat "cannot" $patch.op $key "on type" (kindOf $obj)) -}}
      {{- end -}}
    {{- end -}}

    {{- if or (eq $patch.op "add") (eq $patch.op "replace") (eq $patch.op "move") (eq $patch.op "copy") }}
      {{- $key := $patch.pathKey -}}
      {{- $lastMap := $patch.pathLastMap -}}
      {{- $lastKey := $patch.pathLastKey -}}
      {{- $value := $patch.value -}}
      {{- $obj := index $lastMap $lastKey -}}

      {{- if kindIs "map" $obj -}}
        {{- $_ := set $obj $key $value -}}

      {{- else if kindIs "slice" $obj -}}
        {{- $i := 0 -}}
        {{- if eq $key "-" -}}
          {{- $i = len $obj -}}
        {{- else -}}
          {{- $i = atoi $key -}}
          {{- if ne $key (toString $i) -}}
            {{- fail (cat "cannot convert" $key "to int") -}}
          {{- end -}}
        {{- end -}}
        {{- if lt $i 0 -}}
          {{- fail "slice index <0" -}}
        {{- else if eq $i 0 -}}
          {{- $_ := set $lastMap $lastKey (prepend $obj $value) -}}
        {{- else if lt $i (len $obj) -}}
          {{- $_ := set $lastMap $lastKey (concat (append (slice $obj 0 $i) $value) (slice $obj $i)) -}}
        {{- else if eq $i (len $obj) -}}
          {{- $_ := set $lastMap $lastKey (append $obj $value) -}}
        {{- else -}}
          {{- fail "slice index > slice length" -}}
        {{- end -}}

      {{- else -}}
        {{- fail (cat "cannot" $patch.op $key "on type" (kindOf $obj)) -}}
      {{- end -}}
    {{- end -}}

    {{- if eq $patch.op "test" }}
      {{- if not (deepEqual $patch.value $patch.testValue) }}
        {{- fail (cat "test failed, expected" (toJson $patch.value) "but got" (toJson $patch.testValue)) -}}
      {{- end -}}
    {{- end -}}

    {{- range $reSliceOp := $reSlice -}}
      {{- $sliceObj := list -}}
      {{- range $i := until (len $reSliceOp.mapObj) -}}
        {{- $sliceObj = append $sliceObj (index $reSliceOp.mapObj (toString $i)) -}}
      {{- end -}}
      {{- $_ := set $reSliceOp.lastMap $reSliceOp.lastKey $sliceObj -}}
    {{- end -}}

  {{- end -}}
  {{- toJson $docContainer -}}
{{- end -}}
