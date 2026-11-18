[CmdletBinding()]
param([ValidateSet('x86_64','x86','arm64-v8a','armeabi-v7a')][string]$Abi = 'x86_64', [switch]$TestBinary)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputRoot = Join-Path $projectRoot '.tmp/android-lab/identity-tools'
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$savedEnv = @{}
foreach ($name in @('GOOS','GOARCH','GOARM','CGO_ENABLED','GOCACHE','GOTMPDIR')) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $env:GOOS = 'linux'
    $env:GOARCH = @{ 'x86_64'='amd64'; 'x86'='386'; 'arm64-v8a'='arm64'; 'armeabi-v7a'='arm' }[$Abi]
    $env:GOARM = '7'
    $env:CGO_ENABLED = '0'
    $env:GOCACHE = Join-Path $projectRoot '.test-go-cache'
    $env:GOTMPDIR = Join-Path $projectRoot '.test-tmp'
    New-Item -ItemType Directory -Force -Path $env:GOTMPDIR | Out-Null
    $output = Join-Path $outputRoot "propwriter-$Abi"
    Push-Location $projectRoot
    try {
        if ($TestBinary) {
            $output += '.test'
            & go test -c -o $output ./tools/android-propwriter
        } else { & go build -trimpath -o $output ./tools/android-propwriter }
    } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw 'Android property writer build failed.' }
    Write-Host "Built: $output"
} finally {
    foreach ($name in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process') }
}
