#!/usr/bin/env bash
# Run from the repository root after copying the kit in.
set -euo pipefail
gofmt -l ./pkg/internal/webui | tee /tmp/gofmt.out
test ! -s /tmp/gofmt.out
go vet ./pkg/internal/webui/... .
go build ./...
go test ./pkg/internal/webui/... . -count=1
go test -race ./pkg/internal/webui/... -run "Job|Stream|Host" -count=1
