#!/usr/bin/env bash
#
# Minify a self-contained HTML file (with inlined <style> and <script>).
#
# Uses html-minifier-terser via `npx`, which runs it from npx's cache without
# touching the repo's package.json / node_modules. The first invocation will
# download the package; subsequent runs are instant.
#
# Usage:
#     resources/scripts/minify_html.sh [--gzip] path/to/file.html
#
# Writes `path/to/file.ext.min` next to the source, and with --gzip also
# `path/to/file.ext.min.gz` for pages that are served pre-compressed.

set -euo pipefail

gzip_output=0
if [[ "${1:-}" == "--gzip" ]]; then
    gzip_output=1
    shift
fi

if [[ $# -ne 1 ]]; then
    echo "usage: $(basename "$0") [--gzip] <file.html>" >&2
    exit 1
fi

src="$1"

if [[ ! -f "$src" ]]; then
    echo "error: not a file: $src" >&2
    exit 1
fi

if ! command -v npx >/dev/null 2>&1; then
    echo "error: npx not found in PATH (install Node.js)" >&2
    exit 1
fi

# login.html -> login.min.html
dir=$(dirname -- "$src")
base=$(basename -- "$src")
stem="${base%.*}"
ext="${base##*.}"
dst="$dir/$stem.$ext.min"

npx -y html-minifier-terser@latest \
    --collapse-whitespace \
    --conservative-collapse \
    --remove-comments \
    --minify-css true \
    --minify-js true \
    --decode-entities \
    -o "$dst" \
    "$src"

before=$(wc -c < "$src" | tr -d ' ')
after=$(wc -c < "$dst" | tr -d ' ')
saved=$((before - after))
pct=$(awk "BEGIN { printf \"%.1f\", ($saved / $before) * 100 }")

echo "$src -> $dst"
echo "  $before B -> $after B  ($saved B, $pct% smaller)"

if [ "$gzip_output" = "1" ]; then
    gzip -9 -n -c "$dst" > "$dst.gz"
    gz=$(wc -c < "$dst.gz" | tr -d ' ')
    gzpct=$(awk "BEGIN { printf \"%.1f\", (($before - $gz) / $before) * 100 }")
    echo "  gzip: $dst.gz  $gz B  ($gzpct% smaller than source)"
fi
