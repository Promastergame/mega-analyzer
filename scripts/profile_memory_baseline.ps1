param(
    [string]$BinaryPath = 'analyzer.exe',
    [string]$ProfileName = 'quick',
    [string]$RunName = 'baseline'
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$runDir = Join-Path $root ("analysis_output\perf-audit-20260820-" + $RunName)
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$heapProfile = Join-Path $runDir 'baseline.heap.pprof'
$samplesPath = Join-Path $runDir 'process_samples.csv'
$summaryPath = Join-Path $runDir 'summary.json'
$stdoutPath = Join-Path $runDir 'analyzer.stdout.log'
$stderrPath = Join-Path $runDir 'analyzer.stderr.log'

Remove-Item -Force -ErrorAction SilentlyContinue $heapProfile, $samplesPath, $summaryPath, $stdoutPath, $stderrPath

$env:ANALYZER_OUTPUT_DIR = $runDir
$exe = if ([System.IO.Path]::IsPathRooted($BinaryPath)) { $BinaryPath } else { Join-Path $root $BinaryPath }
$args = @(
    '-t', 'demo\vulnerable-app',
    '-profile', $ProfileName,
    '-report', 'short',
    '-quiet',
    '-mem-profile', $heapProfile
)

$startedAt = Get-Date
$process = Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $root -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
$samples = [System.Collections.Generic.List[object]]::new()

while (-not $process.HasExited) {
    $current = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
    if ($null -ne $current) {
        $samples.Add([PSCustomObject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
            WorkingSetMB = [Math]::Round($current.WorkingSet64 / 1MB, 2)
            PrivateMB = [Math]::Round($current.PrivateMemorySize64 / 1MB, 2)
            VirtualMB = [Math]::Round($current.VirtualMemorySize64 / 1MB, 2)
            ThreadCount = $current.Threads.Count
            HandleCount = $current.HandleCount
            CpuSeconds = [Math]::Round($current.TotalProcessorTime.TotalSeconds, 3)
        })
    }
    Start-Sleep -Milliseconds 250
}

$process.WaitForExit()
$process.Refresh()
$exitCode = $process.ExitCode
$endedAt = Get-Date
$samples | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $samplesPath

$peakWorkingSet = if ($samples.Count) { ($samples | Measure-Object -Property WorkingSetMB -Maximum).Maximum } else { 0 }
$peakPrivate = if ($samples.Count) { ($samples | Measure-Object -Property PrivateMB -Maximum).Maximum } else { 0 }
$peakThreads = if ($samples.Count) { ($samples | Measure-Object -Property ThreadCount -Maximum).Maximum } else { 0 }

[PSCustomObject]@{
    startedAtUtc = $startedAt.ToUniversalTime().ToString('o')
    endedAtUtc = $endedAt.ToUniversalTime().ToString('o')
    elapsedSeconds = [Math]::Round(($endedAt - $startedAt).TotalSeconds, 3)
    exitCode = $exitCode
    sampleCount = $samples.Count
    peakWorkingSetMB = $peakWorkingSet
    peakPrivateMB = $peakPrivate
    peakThreadCount = $peakThreads
    heapProfile = $heapProfile
    outputDirectory = $runDir
    binaryPath = $exe
    profile = $ProfileName
} | ConvertTo-Json | Set-Content -Encoding UTF8 -Path $summaryPath

if ($exitCode -ne 0) {
    exit $exitCode
}
