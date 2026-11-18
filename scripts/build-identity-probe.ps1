[CmdletBinding()]
param(
    [string]$SdkRoot = "$env:LOCALAPPDATA/Android/Sdk",
    [string]$ToolsDir = '',
    [string]$JavaHome = 'C:/Program Files/Eclipse Adoptium/jdk-17.0.17.10-hotspot'
)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $ToolsDir) { $ToolsDir = Join-Path $projectRoot 'tools/windows' }
$sourceRoot = Join-Path $projectRoot 'labs/android-identity-probe'
$buildRoot = Join-Path $projectRoot '.tmp/android-lab/identity-probe'
$classes = Join-Path $buildRoot 'classes'
$java = Join-Path $JavaHome 'bin/java.exe'
$javac = Join-Path $JavaHome 'bin/javac.exe'
$aapt = Join-Path $SdkRoot 'build-tools/36.0.0/aapt.exe'
$androidJar = Join-Path $ToolsDir 'android.jar'
$d8 = Join-Path $ToolsDir 'd8.jar'
$signer = Join-Path $ToolsDir 'apksigner.jar'
$keystore = Join-Path $ToolsDir 'debug.keystore'
foreach ($inputPath in @($java, $javac, $aapt, $androidJar, $d8, $signer, $keystore)) {
    if (-not (Test-Path -LiteralPath $inputPath)) { throw "Build input not found: $inputPath" }
}
New-Item -ItemType Directory -Force -Path $classes | Out-Null
$source = Join-Path $sourceRoot 'src/com/megaanalyzer/identityprobe/ProbeActivity.java'
& $javac -source 8 -target 8 -Xlint:-options -bootclasspath $androidJar -d $classes $source
if ($LASTEXITCODE -ne 0) { throw 'Identity probe compilation failed.' }
$classFiles = @(Get-ChildItem -LiteralPath $classes -Recurse -Filter '*.class' | Select-Object -ExpandProperty FullName)
& $java -cp $d8 com.android.tools.r8.D8 --debug --lib $androidJar --min-api 23 --output $buildRoot @classFiles
if ($LASTEXITCODE -ne 0) { throw 'Identity probe DEX build failed.' }
$unsigned = Join-Path $buildRoot 'unsigned.apk'
& $aapt package -f -M (Join-Path $sourceRoot 'AndroidManifest.xml') -I $androidJar -F $unsigned
if ($LASTEXITCODE -ne 0) { throw 'Identity probe APK packaging failed.' }
Push-Location $buildRoot
try {
    & $aapt add $unsigned classes.dex
    if ($LASTEXITCODE -ne 0) { throw 'Identity probe DEX packaging failed.' }
} finally { Pop-Location }
$output = Join-Path $buildRoot 'identity-probe.apk'
& $java -jar $signer sign --ks $keystore --ks-pass pass:android --out $output $unsigned
if ($LASTEXITCODE -ne 0) { throw 'Identity probe signing failed.' }
Write-Host "Built: $output"
