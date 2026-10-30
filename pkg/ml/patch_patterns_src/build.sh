#!/usr/bin/env bash
# Rebuild ../patch_patterns.json from the per-category source files here.
# Concatenation order comes from _manifest.json. Fails on a missing manifest
# file or a duplicate pattern id, so the src tree always round-trips to the
# embedded runtime file (see patch_data_embed.go).
#
# Usage:
#   ./build.sh          # regenerate ../patch_patterns.json
#   ./build.sh --check  # validate only: manifest complete + ids unique
set -eu
cd "$(dirname "$0")"

manifest=_manifest.json
out=../patch_patterns.json

command -v jq >/dev/null 2>&1 || { echo "build.sh: jq is required" >&2; exit 1; }

files=$(jq -r '.[]' "$manifest")

missing=0
for f in $files; do
  [ -f "$f" ] || { echo "build.sh: manifest references missing file: $f" >&2; missing=1; }
done
[ "$missing" -eq 0 ] || exit 1

merged=$(jq -s 'add' $files)

dupes=$(echo "$merged" | jq -r '[.[].id]|group_by(.)|map(select(length>1))|map(.[0])|.[]')
if [ -n "$dupes" ]; then
  echo "build.sh: duplicate pattern ids:" >&2
  echo "$dupes" >&2
  exit 1
fi

count=$(echo "$merged" | jq 'length')

if [ "${1:-}" = "--check" ]; then
  echo "build.sh: OK - $count patterns, ids unique, manifest complete"
  exit 0
fi

echo "$merged" | jq '.' | sed 's/$/\r/' > "$out"
echo "build.sh: wrote $out ($count patterns)"
