@echo off
setlocal
cd /d "%~dp0"
set CGO_ENABLED=0
set GOAMD64=v1
if not exist bin mkdir bin
set "CANDIDATE=bin\dai-go.candidate.exe"
go build -trimpath -ldflags="-s -w" -o "%CANDIDATE%" ./cmd/dai || exit /b 1
go test ./... -count=1 || (del /q "%CANDIDATE%" 2>nul & exit /b 1)
go vet ./... || (del /q "%CANDIDATE%" 2>nul & exit /b 1)
move /y "%CANDIDATE%" bin\dai-go.exe >nul || exit /b 1
echo OK: bin\dai-go.exe. Native and legacy binaries were not overwritten.
echo Run RUN-DAI.cmd serve
