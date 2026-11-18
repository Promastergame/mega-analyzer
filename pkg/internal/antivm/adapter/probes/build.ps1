param([string]$SdkRoot = (Join-Path $env:LOCALAPPDATA 'Android\Sdk'))
$ErrorActionPreference = 'Stop'
$taskProbeDir = $PSScriptRoot
$taskCompileDir = Join-Path ([IO.Path]::GetTempPath()) ('mega-sensor-probe-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskCompileDir | Out-Null
try {
    $taskPlatform = Get-ChildItem -LiteralPath (Join-Path $SdkRoot 'platforms') -Directory | Sort-Object { [int]($_.Name -replace '^android-', '') } -Descending | Select-Object -First 1
    $taskTools = Get-ChildItem -LiteralPath (Join-Path $SdkRoot 'build-tools') -Directory | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    & javac --release 8 -classpath (Join-Path $taskPlatform.FullName 'android.jar') -d $taskCompileDir (Join-Path $taskProbeDir 'MegaSensorProbe.java')
    if ($LASTEXITCODE -ne 0) { throw 'javac failed' }
    $taskClasses = @(Get-ChildItem -LiteralPath $taskCompileDir -Filter '*.class' | ForEach-Object { $_.FullName })
    & (Join-Path $taskTools.FullName 'd8.bat') --min-api 28 --lib (Join-Path $taskPlatform.FullName 'android.jar') --output $taskCompileDir @taskClasses
    if ($LASTEXITCODE -ne 0) { throw 'd8 failed' }
    Copy-Item -LiteralPath (Join-Path $taskCompileDir 'classes.dex') -Destination (Join-Path $taskProbeDir 'sensors.dex')
} finally {
    $taskResolved = [IO.Path]::GetFullPath($taskCompileDir)
    $taskTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (!$taskResolved.StartsWith($taskTempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'unexpected build cleanup path' }
    Remove-Item -LiteralPath $taskResolved -Recurse -Force
}
