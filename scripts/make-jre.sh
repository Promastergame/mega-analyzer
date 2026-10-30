#!/usr/bin/env bash
# Builds the minimal Java runtime that can be embedded into the analyzer
# (go build -tags embedjre). Needs a full JDK (jlink) for the HOST and, for
# cross targets, the target JDK's jmods directory.
#
#   scripts/make-jre.sh linux-amd64   /path/to/host-jdk
#   scripts/make-jre.sh windows-amd64 /path/to/host-jdk /path/to/windows-jdk
#
# Result: pkg/internal/apkloader/embedtools/jre-<os>-<arch>.tgz (~23-26 MB).
# Modules: java.base (smali/baksmali core), java.xml (baksmali), java.logging.
set -euo pipefail
target="${1:?usage: make-jre.sh <os-arch> <host-jdk> [target-jdk]}"
host_jdk="${2:?host JDK path}"
target_jdk="${3:-$host_jdk}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/pkg/internal/apkloader/embedtools"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
"$host_jdk/bin/jlink" \
  --module-path "$target_jdk/jmods" \
  --add-modules java.base,java.xml,java.logging \
  --compress zip-9 --strip-debug --no-header-files --no-man-pages \
  --output "$tmp/jre"
tar -C "$tmp/jre" -czf "$out/jre-$target.tgz" .
ls -l "$out/jre-$target.tgz"
