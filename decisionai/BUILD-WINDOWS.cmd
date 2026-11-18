@echo off
setlocal
cd /d "%~dp0"
where go >nul 2>nul
if errorlevel 1 (echo Go 1.22+ is required. Install Go, then run this script again. & exit /b 1)
set CGO_ENABLED=0
set GOAMD64=v1
go test ./... -count=1
if errorlevel 1 exit /b 1
go vet ./...
if errorlevel 1 exit /b 1
if not exist bin mkdir bin
go build -trimpath -ldflags="-s -w" -o bin\decision-ai.exe ./cmd/decision-ai
go build -trimpath -ldflags="-s -w" -o bin\smali-role.exe ./cmd/smali-role
if errorlevel 1 exit /b 1
echo Built bin\decision-ai.exe. No AVX2 or CUDA required.
endlocal
