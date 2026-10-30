#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v go >/dev/null || { echo 'Go from go.mod is required; no toolchain will be installed.' >&2; exit 1; }
command -v gofmt >/dev/null || { echo 'gofmt is required.' >&2; exit 1; }
# Format only the files changed by this feature, not the whole repository.
files=(
  pkg/internal/jarloader/{analyzer.go,classfile.go,bytecode.go,bytecode_findings.go,bytecode_test.go}
  pkg/internal/apkloader/extractor.go pkg/internal/types/{analysis_result.go,jvm_evidence_test.go}
  pkg/cmd/analyzer/web/{assets.go,handlers_scan.go,handlers_workspace.go,job.go,router.go,runner.go,security.go,server.go,workspace.go,workspace_test.go,scan_flags.go}
)
gofmt -w "${files[@]}"
go test -count=1 ./pkg/internal/jarloader ./pkg/internal/types ./pkg/cmd/analyzer/web
go vet ./pkg/internal/jarloader ./pkg/internal/types ./pkg/cmd/analyzer/web
if [[ "${RACE:-0}" == 1 ]]; then go test -race -count=1 ./pkg/internal/jarloader ./pkg/cmd/analyzer/web; fi
if [[ "${FUZZ:-0}" == 1 ]]; then go test ./pkg/internal/jarloader -run '^$' -fuzz '^FuzzInstructionBoundaries$' -fuzztime=30s; fi
if [[ "${INTEGRATION:-0}" == 1 ]]; then go test -count=1 ./pkg/internal/apkloader ./pkg/cmd/analyzer ./pkg/minecraft; fi
if command -v node >/dev/null; then
  node --check pkg/cmd/analyzer/web/assets/app.js
  node --check pkg/cmd/analyzer/web/assets/workspace.js
  node scripts/test-workspace-ui.cjs
fi
