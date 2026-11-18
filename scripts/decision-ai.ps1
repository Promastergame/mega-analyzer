# Local DecisionAI lifecycle and static analyzer integration (PowerShell 7, Windows).
[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop', 'Status', 'Build', 'Scan')]
    [string]$Action = 'Start',
    [ValidateRange(1024, 65535)][int]$Port = 7480,
    [string]$Target,
    [string]$Output = 'outputs/decisionai-scan',
    [ValidateRange(1, 512)][int]$MaxFindings = 64,
    [ValidateRange(1, 300)][int]$Budget = 30,
    [switch]$Rebuild
)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This helper uses Windows DPAPI and hidden Windows processes.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$decisionRoot = Join-Path $projectRoot 'decisionai'
$decisionExe = Join-Path $decisionRoot 'bin/dai.exe'
$analyzerExe = Join-Path $projectRoot 'bin/analyzer-decisionai.exe'
$runtimeDir = Join-Path $decisionRoot '.runtime/mega-analyzer'
$stateFile = Join-Path $runtimeDir 'service.json'
$tokenFile = Join-Path $runtimeDir 'api-token.dpapi'
$origin = "http://127.0.0.1:$Port"
if (-not (Test-Path -LiteralPath (Join-Path $decisionRoot 'go.mod'))) { throw "Local DecisionAI project is missing: $decisionRoot" }
[void](New-Item -ItemType Directory -Force -Path $runtimeDir)

function Get-OwnedService {
    if (-not (Test-Path -LiteralPath $stateFile)) { return $null }
    $state = Get-Content -Raw -LiteralPath $stateFile | ConvertFrom-Json
    try { $proc = Get-Process -Id $state.pid -ErrorAction Stop } catch { return $null }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($proc.Path, $decisionExe) -or
        $proc.StartTime.ToUniversalTime().Ticks -ne ([datetime]$state.started_utc).ToUniversalTime().Ticks) {
        throw 'Saved PID belongs to a different process; it will not be stopped or reused.'
    }
    if ($state.port -ne $Port) { throw "Owned service uses port $($state.port); pass -Port $($state.port)." }
    return $proc
}

function Get-ServiceHealth {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(2)
    try {
        $response = $client.GetAsync("$origin/v1/health").GetAwaiter().GetResult()
        try {
            [void]$response.EnsureSuccessStatusCode()
            return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
        } finally { $response.Dispose() }
    } finally { $client.Dispose() }
}

function Import-ServiceToken {
    $secure = (Get-Content -Raw -LiteralPath $tokenFile).Trim() | ConvertTo-SecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $env:DAI_API_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secure.Dispose() }
    $env:MEGA_DECISION_AI_URL = $origin
}

function Build-LocalTools {
    param([switch]$AnalyzerOnly)
    $savedCache, $savedTemp = $env:GOCACHE, $env:GOTMPDIR
    $env:GOCACHE = Join-Path $projectRoot '.test-go-cache'
    $env:GOTMPDIR = Join-Path $projectRoot '.test-tmp'
    [void](New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOTMPDIR, (Split-Path -Parent $decisionExe), (Split-Path -Parent $analyzerExe))
    try {
        if (-not $AnalyzerOnly) {
            Push-Location $decisionRoot
            try {
                & go build -trimpath -o $decisionExe ./cmd/dai
                if ($LASTEXITCODE -ne 0) { throw 'DecisionAI build failed.' }
            } finally { Pop-Location }
        }
        Push-Location $projectRoot
        try {
            & go build -trimpath -tags noembed -o $analyzerExe ./pkg/cmd/analyzer
            if ($LASTEXITCODE -ne 0) { throw 'Analyzer build failed.' }
        } finally { Pop-Location }
    } finally { $env:GOCACHE, $env:GOTMPDIR = $savedCache, $savedTemp }
}

function Start-LocalService {
    $proc = Get-OwnedService
    if ($null -ne $proc) {
        Import-ServiceToken
        return Get-ServiceHealth
    }
    try { $foreignHealth = Get-ServiceHealth } catch { $foreignHealth = $null }
    if ($null -ne $foreignHealth) { throw 'The port already hosts a service not started by this helper. Use its token explicitly or select another port.' }
    if (-not (Test-Path -LiteralPath $decisionExe)) { Build-LocalTools }
    $token = $env:DAI_API_TOKEN
    if ([string]::IsNullOrEmpty($token)) { $token = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant() }
    $secure = ConvertTo-SecureString $token -AsPlainText -Force
    try { [IO.File]::WriteAllText($tokenFile, (ConvertFrom-SecureString $secure)) }
    finally { $secure.Dispose() }
    $env:DAI_API_TOKEN, $env:MEGA_DECISION_AI_URL = $token, $origin
    $proc = Start-Process -FilePath $decisionExe -ArgumentList @('serve', '-addr', "127.0.0.1:$Port", '-workers', '2') `
        -WorkingDirectory $decisionRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $runtimeDir 'stdout.log') -RedirectStandardError (Join-Path $runtimeDir 'stderr.log')
    $started = $proc.StartTime.ToUniversalTime().ToString('O')
    [IO.File]::WriteAllText($stateFile, (@{ pid = $proc.Id; started_utc = $started; port = $Port; origin = $origin; executable = $decisionExe } | ConvertTo-Json))
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 25) {
        $proc.Refresh()
        if ($proc.HasExited) { throw "DecisionAI exited. Inspect $runtimeDir/stderr.log." }
        try { return Get-ServiceHealth } catch { Start-Sleep -Milliseconds 200 }
    }
    throw "DecisionAI is still starting. Inspect $runtimeDir/stderr.log and run -Action Status."
}

if ($Action -eq 'Stop') {
    $proc = Get-OwnedService
    if ($null -ne $proc) { Stop-Process -Id $proc.Id; Write-Output "Stopped owned DecisionAI PID $($proc.Id)." }
    else { Write-Output 'Owned DecisionAI is not running.' }
    return
}
if ($Action -eq 'Status') {
    $proc = Get-OwnedService
    if ($null -eq $proc) { Write-Output 'Owned DecisionAI is not running.'; return }
    $health = Get-ServiceHealth
    [pscustomobject]@{ pid = $proc.Id; url = $origin; status = $health.status; backend = $health.backend; version = $health.version }
    return
}
if ($Action -eq 'Build' -or $Rebuild) {
    if ($null -ne (Get-OwnedService)) { throw 'Stop the owned service before rebuilding its executable.' }
    Build-LocalTools
    if ($Action -eq 'Build') { Write-Output 'Built DecisionAI and analyzer from local source.'; return }
}
if ($Action -eq 'Scan' -and [string]::IsNullOrWhiteSpace($Target)) { throw 'Scan requires -Target.' }
if ($Action -eq 'Scan' -and -not (Test-Path -LiteralPath $analyzerExe)) { Build-LocalTools -AnalyzerOnly }
$health = Start-LocalService
Write-Output "DecisionAI ready: $origin; backend $($health.backend); version $($health.version). Token is kept in the process environment and protected with DPAPI."
if ($Action -eq 'Scan') {
    Push-Location $projectRoot
    try {
        & $analyzerExe -target $Target -output $Output -profile paranoid -top5 -mobsf-all -sbom -permmap -cert-audit -malware-domains -niap -sarif `
            -decision-ai-url $origin -decision-ai-max-findings $MaxFindings -decision-ai-budget $Budget -quiet -no-color
        if ($LASTEXITCODE -ne 0) { throw "Analyzer exited with code $LASTEXITCODE; inspect its coverage and verdict in the output." }
    } finally { Pop-Location }
}
