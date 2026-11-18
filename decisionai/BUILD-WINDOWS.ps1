$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:CGO_ENABLED = '0'
$env:GOAMD64 = 'v1'
go test ./... -count=1
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
go vet ./...
if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
New-Item -ItemType Directory -Force bin | Out-Null
go build -trimpath -ldflags='-s -w' -o bin/decision-ai.exe ./cmd/decision-ai
go build -trimpath -ldflags='-s -w' -o bin/smali-role.exe ./cmd/smali-role
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
