param(
    [string]$ToolsDir = "",
    [string]$Output = "demo_test_apk.apk",
    [int]$ApiLevel = 35
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (-not $ToolsDir) { $ToolsDir = Join-Path (Split-Path (Split-Path $root)) "tools\windows" }
$aapt2 = Join-Path $ToolsDir "aapt2.exe"
$zipalign = Join-Path $ToolsDir "zipalign.exe"
$androidJar = Join-Path $ToolsDir "android.jar"
$debugKeystore = Join-Path $ToolsDir "debug.keystore"
$d8 = Get-ChildItem -LiteralPath $ToolsDir -Filter "d8*.jar" | Select-Object -First 1
$ecj = Get-ChildItem -LiteralPath $ToolsDir -Filter "ecj*.jar" | Select-Object -First 1
$apksigner = Get-ChildItem -LiteralPath $ToolsDir -Filter "apksigner*.jar" | Select-Object -First 1

foreach ($path in @($aapt2, $zipalign, $androidJar, $debugKeystore)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "missing tool or input: $path" }
}
foreach ($jar in @($d8, $ecj, $apksigner)) {
    if ($null -eq $jar) { throw "missing Android tool jar in $ToolsDir" }
}
if (-not (Get-Command java -ErrorAction SilentlyContinue)) { throw "java is not on PATH" }

$build = Join-Path $root "build"
Remove-Item -LiteralPath $build -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$build\obj", "$build\gen", "$build\classes" | Out-Null

& $aapt2 compile --dir (Join-Path $root "res") -o "$build\obj\res.zip"
if ($LASTEXITCODE -ne 0) { throw "aapt2 compile failed" }
& $aapt2 link -o "$build\unsigned.apk" -I $androidJar --manifest (Join-Path $root "AndroidManifest.xml") --java "$build\gen" --min-sdk-version 23 --target-sdk-version $ApiLevel "$build\obj\res.zip"
if ($LASTEXITCODE -ne 0) { throw "aapt2 link failed" }

$sources = @(Get-ChildItem -Recurse -Filter *.java -Path (Join-Path $root "src"), "$build\gen" | ForEach-Object { $_.FullName })
& java -jar $ecj.FullName -source 8 -target 8 -nowarn -cp $androidJar -d "$build\classes" $sources
if ($LASTEXITCODE -ne 0) { throw "ecj failed" }
$classes = @(Get-ChildItem -Recurse -Filter *.class -Path "$build\classes" | ForEach-Object { $_.FullName })
& java -cp $d8.FullName com.android.tools.r8.D8 --debug --lib $androidJar --min-api 23 --output $build @classes
if ($LASTEXITCODE -ne 0) { throw "d8 failed" }

Push-Location $build
try {
    & jar uf "unsigned.apk" "classes.dex"
    & jar uf "unsigned.apk" -C (Join-Path $root "assets") pseudo_ad.svg
    & jar uf "unsigned.apk" -C (Join-Path $root "react_native") index.android.bundle
} finally { Pop-Location }

& $zipalign -f -p 4 "$build\unsigned.apk" "$build\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw "zipalign failed" }
& java -jar $apksigner.FullName sign --ks $debugKeystore --ks-pass pass:android --out (Join-Path $build $Output) "$build\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }
Write-Host "built $(Join-Path $build $Output)"
