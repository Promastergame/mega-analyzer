<#
.SYNOPSIS
Build the Windows Mega-Analyzer binary with native GNN support enabled.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Version 1.0.0-beta.1
#>
[CmdletBinding()]
param(
    [string]$Version = $(Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw).Trim()
)

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
$outputDir = Join-Path $projectRoot "bin"
$rustManifest = Join-Path $projectRoot "rust\Cargo.toml"
$gnnDLL = Join-Path $projectRoot "rust\target\release\omnisec_ml_gnn.dll"
$analyzerEXE = Join-Path $outputDir "analyzer.exe"
$buildDate = Get-Date -Format "yyyy-MM-dd"
$buildCommit = (& git -C $projectRoot rev-parse HEAD).Trim()

foreach ($tool in "cargo", "go", "zig") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required tool '$tool' was not found in PATH."
    }
}

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Push-Location $projectRoot
try {
    Write-Host "[1/3] Building Rust GNN library..." -ForegroundColor Cyan
    & cargo build --manifest-path $rustManifest --release -p omnisec-ml-gnn

    if (-not (Test-Path -LiteralPath $gnnDLL)) {
        throw "GNN DLL was not produced: $gnnDLL"
    }

    Write-Host "[2/3] Building analyzer.exe with GNN support..." -ForegroundColor Cyan
    $previousCGO = $env:CGO_ENABLED
    $previousCC = $env:CC
    try {
        $env:CGO_ENABLED = "1"
        $env:CC = "zig cc"
        $linkFlags = "-s -w -X main.Version=$Version -X main.BuildDate=$buildDate -X main.CommitHash=$buildCommit"
        & go build "-tags=omnisec_ml_gnn" -trimpath "-ldflags=$linkFlags" -o $analyzerEXE ./pkg/cmd/analyzer
    } finally {
        $env:CGO_ENABLED = $previousCGO
        $env:CC = $previousCC
    }

    Write-Host "[3/4] Copying GNN runtime DLL..." -ForegroundColor Cyan
    Copy-Item -LiteralPath $gnnDLL -Destination $outputDir -Force
    if (Test-Path -LiteralPath (Join-Path $projectRoot "analyzer.exe")) {
        Copy-Item -LiteralPath $analyzerEXE -Destination (Join-Path $projectRoot "analyzer.exe") -Force
    }

    Write-Host "[4/4] Building standalone decompiler.exe (no Java/SDK)..." -ForegroundColor Cyan
    $decompilerEXE = Join-Path $outputDir "decompiler.exe"
    & go build -trimpath "-ldflags=-s -w -X mega-analyzer/pkg/buildinfo.Version=$Version -X mega-analyzer/pkg/buildinfo.BuildDate=$buildDate -X mega-analyzer/pkg/buildinfo.CommitHash=$buildCommit" -o $decompilerEXE ./cmd/decompiler

} finally {
    Pop-Location
}

Write-Host "Done: $analyzerEXE" -ForegroundColor Green
Write-Host "Run:  .\bin\analyzer.exe -t .\app.apk -gnn-model .\rust\gnn_weights.gnnbuf" -ForegroundColor Green
