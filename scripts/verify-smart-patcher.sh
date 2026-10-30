#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
go test ./pkg/ml ./cmd/patch-apk
echo "Smart patcher verification passed. Run zig build test in the separate apk-editor repository for IDE checks."
