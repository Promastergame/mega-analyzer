#!/usr/bin/env bash
# Run from any directory after installing the Go version required by go.mod.
set -euo pipefail
cd "$(dirname "$0")/.."
# Use the installed toolchain as-is: never attempt a network toolchain
# switch (a bare MSYS/system go would otherwise try to download go1.27.1).
export GOTOOLCHAIN=local
command -v go >/dev/null || { echo 'Install the Go version required by go.mod first.' >&2; exit 1; }
go test -count=1 -timeout=5m ./pkg/internal/jarloader ./pkg/minecraft ./cmd/minecraft-analyze
go vet ./pkg/internal/jarloader ./pkg/minecraft ./cmd/minecraft-analyze
if [[ "${RACE:-0}" == 1 ]]; then
  go test -race -count=1 -timeout=10m ./pkg/internal/jarloader ./pkg/minecraft
fi
if [[ "${FUZZ:-0}" == 1 ]]; then
  go test ./pkg/internal/jarloader -run='^$' -fuzz=FuzzParseClassNoPanic -fuzztime=30s
fi
if [[ "${INTEGRATION:-0}" == 1 ]]; then
  go test -count=1 -timeout=10m ./pkg/internal/apkloader ./pkg/cmd/analyzer/web ./pkg/cmd/analyzer
fi
