[CmdletBinding()]
param(
    [ValidateSet('Setup', 'Start', 'Status', 'Stop', 'AntiVM', 'Identity')]
    [string]$Action = 'Status',
    [string]$SdkRoot = "$env:LOCALAPPDATA/Android/Sdk",
    [string]$EmulatorPath = '',
    [string]$HttpProxy = '',
    [string]$ImageArchive = '',
    [ValidateSet(24, 25, 28, 35)]
    [int]$ApiLevel = 35,
    [string]$AvdName = '',
    [string]$ProfilePath = '',
    [string]$PropertyWriterFile = '',
    [string]$PhoneNumber = '',
    [switch]$Restart,
    [switch]$MaskIdentity,
    [ValidateRange(5554, 5682)]
    [int]$Port = 5570,
    [ValidateSet('auto', 'off')]
    [string]$Acceleration = 'auto',
    [ValidateSet('swiftshader', 'off', 'auto')]
    [string]$GpuMode = 'swiftshader',
    [ValidateRange(60, 900)]
    [int]$BootTimeoutSeconds = 240,
    [switch]$ShowWindow
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$labRoot = Join-Path $projectRoot '.tmp/android-lab'
$SdkRoot = [IO.Path]::GetFullPath($SdkRoot)
$adb = Join-Path $SdkRoot 'platform-tools/adb.exe'
$emulator = Join-Path $SdkRoot 'emulator/emulator.exe'
if ($EmulatorPath) { $emulator = [IO.Path]::GetFullPath($EmulatorPath) }
$sdkManager = Join-Path $SdkRoot 'cmdline-tools/latest/bin/sdkmanager.bat'
$avdManager = Join-Path $SdkRoot 'cmdline-tools/latest/bin/avdmanager.bat'
$serial = "emulator-$Port"
$systemTag = if ($ApiLevel -lt 35) { 'default' } else { 'google_apis' }
$deviceName = if ($ApiLevel -lt 35) { 'pixel_3' } else { 'pixel_8' }
$image = "system-images;android-$ApiLevel;$systemTag;x86_64"
if ($AvdName -eq '') { $AvdName = "MegaAnalyzer_API_$ApiLevel" }
$selectedProfilePath = ''
if ($ApiLevel -in @(28, 35)) {
    $selectedProfilePath = Join-Path $projectRoot "pkg/internal/antivm/profiles/promasterphone-1-avd-api-$ApiLevel.json"
}
if ($ProfilePath) { $selectedProfilePath = [IO.Path]::GetFullPath($ProfilePath) }

$normalizedPhoneNumber = ''
if ($PhoneNumber) {
    if ($Action -ne 'Start') { throw '-PhoneNumber is a launch option; use -Action Start.' }
    $phoneNumberInput = $PhoneNumber.Trim()
    if ($phoneNumberInput -notmatch '\A\+?[0-9 ()-]+\z') { throw 'Phone number must contain digits and optional +, spaces, parentheses or hyphens.' }
    $normalizedPhoneNumber = $phoneNumberInput -replace '[+ ()-]', ''
    if ($normalizedPhoneNumber -notmatch '\A[0-9]{1,15}\z') { throw 'Phone number must contain 1 to 15 decimal digits.' }
}
if ($Restart -and $Action -ne 'Start') { throw '-Restart is supported only with -Action Start.' }

if ($Port % 2 -ne 0) { throw 'The emulator console port must be even.' }
if ($AvdName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw 'Invalid AVD name.' }
foreach ($binary in @($adb, $emulator)) {
    if (-not (Test-Path -LiteralPath $binary)) { throw "SDK tool not found: $binary" }
}
New-Item -ItemType Directory -Force -Path $labRoot | Out-Null

function Assert-LabDevice {
    $name = & $adb -s $serial emu avd name 2>&1
    $reportedName = ''
    foreach ($line in @($name)) {
        $candidate = [string]$line
        if ($candidate.Trim() -eq $AvdName) { $reportedName = $candidate.Trim(); break }
    }
    if ($LASTEXITCODE -ne 0 -or $reportedName.Trim() -ne $AvdName) {
        throw "Cannot confirm that $serial is lab AVD '$AvdName' (ADB response: $name)."
    }
}

function Stop-LabDevice {
    Assert-LabDevice
    & $adb -s $serial emu kill
    if ($LASTEXITCODE -ne 0) { throw 'Emulator shutdown failed.' }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $devices = & $adb devices
        if ($LASTEXITCODE -ne 0) { throw 'Cannot confirm emulator shutdown.' }
        if ("$devices" -notmatch "(?m)\b$([regex]::Escape($serial))\s") { break }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Emulator remains connected after shutdown.' }
        Start-Sleep -Milliseconds 500
    } while ($true)
}

function Test-LabReady {
    # Windows PowerShell 5.1 can turn redirected native stderr into a
    # terminating error. A device that is not registered yet is expected
    # during boot; let Start check the emulator process and retry.
    try {
        $boot = & $adb -s $serial shell getprop sys.boot_completed 2>$null
        if ($LASTEXITCODE -ne 0 -or "$boot".Trim() -ne '1') { return $false }
        $animation = & $adb -s $serial shell getprop init.svc.bootanim 2>$null
        if ($LASTEXITCODE -ne 0 -or "$animation".Trim() -ne 'stopped') { return $false }
        $package = & $adb -s $serial shell pm path android 2>$null
        return ($LASTEXITCODE -eq 0 -and "$package" -match 'package:')
    } catch {
        return $false
    }
}

function ConvertTo-LabShellArgument([string]$Value) {
    $escape = "'" + [char]34 + "'" + [char]34 + "'"
    return "'" + $Value.Replace("'", $escape) + "'"
}

function Read-AppIdentity([string]$OutputPath) {
    $captureId = [Guid]::NewGuid().ToString('N')
    & $adb -s $serial shell am force-stop com.megaanalyzer.identityprobe | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cannot stop identity probe.' }
    & $adb -s $serial shell am start -W -n com.megaanalyzer.identityprobe/.ProbeActivity --es capture_id $captureId | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cannot start identity probe.' }
    $raw = @(& $adb -s $serial shell cat /data/user/0/com.megaanalyzer.identityprobe/files/identity.json) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read app identity.' }
    $capture = $raw | ConvertFrom-Json
    if ($capture.capture_id -ne $captureId) { throw 'The probe did not produce a fresh app capture.' }
    $raw | Set-Content -LiteralPath $OutputPath -Encoding utf8
    return $capture
}

function Invoke-IdentityMask {
    Assert-LabDevice
    if (-not (Test-LabReady)) { throw 'Android is not ready. Run -Action Start first.' }
    $actualApi = [string](& $adb -s $serial shell getprop ro.build.version.sdk)
    if ($LASTEXITCODE -ne 0 -or $actualApi.Trim() -ne "$ApiLevel") { throw "Expected API $ApiLevel, got $actualApi." }
    $identityProfile = $selectedProfilePath
    if (-not $identityProfile) { throw 'Identity masking on this API requires an explicit -ProfilePath.' }
    $profile = Get-Content -Raw -LiteralPath $identityProfile | ConvertFrom-Json
    $env:GOCACHE = Join-Path $projectRoot '.test-go-cache'
    $env:GOTMPDIR = Join-Path $projectRoot '.test-tmp'
    New-Item -ItemType Directory -Force -Path $env:GOTMPDIR | Out-Null
    $binary = Join-Path $labRoot 'antivm.exe'
    Push-Location $projectRoot
    try { & go build -o $binary ./cmd/antivm } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw 'Anti-VM build failed.' }
    & $binary profile validate $identityProfile
    if ($LASTEXITCODE -ne 0) { throw 'Identity profile is invalid.' }
    if ($profile.api_level -ne $ApiLevel) { throw 'Identity profile API must match the installed Android.' }

    & $adb -s $serial root | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'ADB root failed.' }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-LabReady)) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Root ADB did not reconnect.' }
        Start-Sleep -Milliseconds 500
    }
    $uid = [string](& $adb -s $serial shell id -u)
    if ($LASTEXITCODE -ne 0 -or $uid.Trim() -ne '0') { throw 'Identity masking requires a userdebug AVD with root ADB.' }
    $abi = ([string](& $adb -s $serial shell getprop ro.product.cpu.abi)).Trim()
    $writer = $PropertyWriterFile
    if (-not $writer) {
        & (Join-Path $PSScriptRoot 'build-android-propwriter.ps1') -Abi $abi
        $writer = Join-Path $labRoot "identity-tools/propwriter-$abi"
    }
    if (-not (Test-Path -LiteralPath $writer)) { throw "Property writer not found: $writer" }
    $guestWriter = '/data/local/tmp/mega-antivm/resetprop'
    & $adb -s $serial shell mkdir -p /data/local/tmp/mega-antivm
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create guest helper directory.' }
    & $adb -s $serial push $writer $guestWriter | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cannot upload property writer.' }
    & $adb -s $serial shell chmod 700 $guestWriter
    if ($LASTEXITCODE -ne 0) { throw 'Cannot make property writer executable.' }

    & (Join-Path $PSScriptRoot 'build-identity-probe.ps1') -SdkRoot $SdkRoot
    $probeApk = Join-Path $labRoot 'identity-probe/identity-probe.apk'
    & $adb -s $serial install -r $probeApk | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cannot install identity probe.' }
    & $adb -s $serial shell pm grant com.megaanalyzer.identityprobe android.permission.READ_PHONE_STATE
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant the probe permission to read the virtual SIM.' }
    if ($ApiLevel -ge 26) {
        & $adb -s $serial shell pm grant com.megaanalyzer.identityprobe android.permission.READ_PHONE_NUMBERS
        if ($LASTEXITCODE -ne 0) { throw 'Cannot grant the probe permission to read the phone number.' }
    }
    $runRoot = Join-Path $labRoot ('identity-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
    New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
    $before = Read-AppIdentity (Join-Path $runRoot 'app-before.json')
    $reportText = @(& $binary session start --profile $identityProfile --adb $adb --serial $serial `
        --resetprop $guestWriter --restart-framework --continue-on-failure --timeout 5m `
        --module 'identity,environment,battery,display' --sessions (Join-Path $runRoot 'sessions') --report json) -join "`n"
    $runCode = $LASTEXITCODE
    $reportText | Set-Content -LiteralPath (Join-Path $runRoot 'result.json') -Encoding utf8
    if (-not $reportText.Trim()) { throw "Identity session did not produce a report (exit $runCode)." }
    $report = $reportText | ConvertFrom-Json
    # Android's Settings device name is distinct from android.os.Build.MODEL.
    & $adb -s $serial shell ('settings put global device_name ' + (ConvertTo-LabShellArgument $profile.model))
    if ($LASTEXITCODE -ne 0) { throw 'Cannot set the visible Settings device name.' }
    $after = Read-AppIdentity (Join-Path $runRoot 'app-after.json')
    $checks = @()
    foreach ($field in @('model','brand','manufacturer','device','product','hardware','board','fingerprint','build_id','security_patch')) {
        if ($profile.$field) {
            $checks += [pscustomobject]@{ Field=$field; Expected=$profile.$field; Actual=$after.$field; Passed=($profile.$field -ceq $after.$field) }
        }
    }
    $checks += [pscustomobject]@{ Field='device_name'; Expected=$profile.model; Actual=$after.device_name; Passed=($profile.model -ceq $after.device_name) }
    if ($normalizedPhoneNumber) {
        $actualPhoneNumber = ([string]$after.phone_number) -replace '[^0-9]', ''
        $checks += [pscustomobject]@{ Field='phone_number'; Expected=$normalizedPhoneNumber; Actual=$after.phone_number; Passed=($normalizedPhoneNumber -ceq $actualPhoneNumber) }
    }
    foreach ($field in @('build_type','build_tags')) {
        $expected = if ($field -eq 'build_type') { 'user' } else { 'release-keys' }
        $checks += [pscustomobject]@{ Field=$field; Expected=$expected; Actual=$after.$field; Passed=($expected -ceq $after.$field) }
    }
    $checks | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runRoot 'app-verification.json') -Encoding utf8
    $sessionDir = Get-ChildItem -LiteralPath (Join-Path $runRoot 'sessions') -Directory | Sort-Object Name | Select-Object -Last 1
    if ($sessionDir) {
        & $binary session diff --session $sessionDir.FullName --format json --out (Join-Path $runRoot 'diff.json')
        if ($LASTEXITCODE -ne 0) { throw 'Cannot compare masked device state.' }
    }
    $checks | Format-Table -AutoSize
    Write-Host "Application model: $($before.model) -> $($after.model)"
    Write-Host "Application phone number: $($after.phone_number)"
    $usbConnectedLabel = if ($null -eq $after.usb_connected) { 'unknown' } else { [string]$after.usb_connected }
    Write-Host "Application signals: adb_enabled=$($after.adb_enabled), usb_state_available=$($after.usb_state_available), usb_connected=$usbConnectedLabel"
    Write-Host "Session status: $($report.status); evidence: $runRoot"
    if (@($checks | Where-Object { -not $_.Passed }).Count -gt 0) { throw 'The application-visible identity does not fully match the requested profile.' }
    if ($runCode -ne 0) { throw "Identity was applied, but the full session reported $($report.status). See $runRoot" }
}

$savedEnv = @{}
foreach ($name in @('ANDROID_HOME', 'ANDROID_SDK_ROOT', 'ANDROID_AVD_HOME', 'JAVA_TOOL_OPTIONS', 'GOCACHE', 'GOTMPDIR')) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $env:ANDROID_HOME = $SdkRoot
    $env:ANDROID_SDK_ROOT = $SdkRoot
    if (-not $env:ANDROID_AVD_HOME) {
        $env:ANDROID_AVD_HOME = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.android/avd'
    }
    switch ($Action) {
        'Setup' {
            # Java can choose a broken IPv6 route even when curl reaches Google.
            $env:JAVA_TOOL_OPTIONS = "$env:JAVA_TOOL_OPTIONS -Djava.net.preferIPv4Stack=true".Trim()
            if (-not (Test-Path -LiteralPath (Join-Path $SdkRoot "system-images/android-$ApiLevel/$systemTag/x86_64/system.img"))) {
                if ($ImageArchive) {
                    # Exact official API 35 revision 9 archive, authenticated by
                    # the checksum in Google's HTTPS SDK repository catalogue.
                    if ($ApiLevel -ne 35) { throw '-ImageArchive supports API 35 revision 9 only.' }
                    $archivePath = (Resolve-Path -LiteralPath $ImageArchive).Path
                    if ((Get-Item -LiteralPath $archivePath).Length -ne 1738815903 -or
                        (Get-FileHash -LiteralPath $archivePath -Algorithm SHA1).Hash -ne '0103E6DAB21290C4B9D16550A3CE99476F884EEF') {
                        throw 'Android image archive is incomplete or its official checksum does not match.'
                    }
                    $destination = [IO.Path]::GetFullPath((Join-Path $SdkRoot 'system-images/android-35/google_apis'))
                    if (Test-Path -LiteralPath (Join-Path $destination 'x86_64')) {
                        throw 'An image directory already exists; refusing to overwrite it.'
                    }
                    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
                    try {
                        foreach ($entry in $archive.Entries) {
                            $entryPath = [IO.Path]::GetFullPath((Join-Path $destination $entry.FullName))
                            if (-not $entry.FullName.StartsWith('x86_64/') -or
                                -not $entryPath.StartsWith($destination + [IO.Path]::DirectorySeparatorChar,
                                    [StringComparison]::OrdinalIgnoreCase)) {
                                throw 'Unexpected path in the Android system-image archive.'
                            }
                        }
                    } finally { $archive.Dispose() }
                    Expand-Archive -LiteralPath $archivePath -DestinationPath $destination
                } else {
                    $managerArgs = @($image)
                    if ($HttpProxy) {
                        $proxyUri = [Uri]$HttpProxy
                        if ($proxyUri.Scheme -ne 'http' -or $proxyUri.UserInfo -ne '') {
                            throw '-HttpProxy must be an HTTP proxy URL without embedded credentials.'
                        }
                        $managerArgs += @('--proxy=http', "--proxy_host=$($proxyUri.Host)", "--proxy_port=$($proxyUri.Port)")
                    }
                    & $sdkManager @managerArgs
                    if ($LASTEXITCODE -ne 0) { throw 'Android system-image installation failed.' }
                }
            }
            $names = @(& $emulator -list-avds)
            if ($names -contains $AvdName) {
                Write-Host "AVD already exists: $AvdName"
            } else {
                $avdPath = Join-Path $labRoot "$AvdName.avd"
                $deviceIds = @(& $avdManager list device -c)
                if ($LASTEXITCODE -ne 0) { throw 'Cannot read SDK device definitions.' }
                $selectedDevice = $null
                foreach ($candidate in @($deviceName, 'pixel_7', 'pixel_6', 'pixel_3', 'pixel')) {
                    if ($deviceIds -contains $candidate) { $selectedDevice = $candidate; break }
                }
                if (-not $selectedDevice) { throw 'No supported Pixel screen definition is available in this SDK.' }
                Write-Host "AVD screen definition: $selectedDevice"
                'no' | & $avdManager create avd --name $AvdName --package $image --device $selectedDevice --path $avdPath
                if ($LASTEXITCODE -ne 0) { throw 'AVD creation failed.' }
                Write-Host "Created $AvdName ($avdPath)"
            }
        }
        'Start' {
            $devices = & $adb devices
            if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate ADB devices.' }
            if ("$devices" -match "(?m)\b$([regex]::Escape($serial))\s") {
                Assert-LabDevice
                if ($Restart) {
                    Write-Host "Restarting $AvdName / $serial."
                    Stop-LabDevice
                } else {
                    if ($normalizedPhoneNumber) { throw '-PhoneNumber is applied at launch. Add -Restart to restart this AVD with the requested number.' }
                    if ($MaskIdentity) { Invoke-IdentityMask }
                    Write-Host "$serial is already running."
                    break
                }
            }
            $stdout = Join-Path $labRoot "$AvdName-$Port.stdout.log"
            $stderr = Join-Path $labRoot "$AvdName-$Port.stderr.log"
            # A disposable writable overlay keeps sample changes out of the base AVD.
            $emulatorArgs = @('-avd', $AvdName, '-port', "$Port", '-read-only',
                '-no-snapshot-load', '-no-snapshot-save', '-no-boot-anim', '-no-audio',
                '-gpu', $GpuMode, '-memory', '2048', '-cores', '2')
            if ($Acceleration -eq 'off') { $emulatorArgs += @('-accel', 'off') }
            if ($normalizedPhoneNumber) { $emulatorArgs += @('-phone-number', $normalizedPhoneNumber) }
            if (-not $ShowWindow) { $emulatorArgs += '-no-window' }
            $windowStyle = if ($ShowWindow) { 'Normal' } else { 'Hidden' }
            $process = Start-Process -FilePath $emulator -ArgumentList $emulatorArgs -PassThru -WindowStyle $windowStyle `
                -RedirectStandardOutput $stdout -RedirectStandardError $stderr
            try {
                $deadline = [DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds)
                while (-not (Test-LabReady)) {
                    $process.Refresh()
                    if ($process.HasExited) { throw ("Emulator exited with code 0x{0:X8}. See {1}" -f [int]$process.ExitCode, $stderr) }
                    if ([DateTime]::UtcNow -gt $deadline) { throw "Android boot timed out. See $stderr" }
                    Start-Sleep -Seconds 2
                }
                Assert-LabDevice
                $release = & $adb -s $serial shell getprop ro.build.version.release
                $actualApi = & $adb -s $serial shell getprop ro.build.version.sdk
                if ("$actualApi".Trim() -ne "$ApiLevel") { throw "Expected API $ApiLevel, got $actualApi." }
                Write-Host "Ready: $AvdName / $serial (Android $release, API $actualApi)"
            } catch {
                # The launcher spawns QEMU; stopping only the launcher leaves
                # a failed boot consuming memory and holding the lab port.
                try {
                    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($process.Id)" -ErrorAction Stop)
                    foreach ($child in $children) {
                        if ($child.Name -like 'qemu-system-*') {
                            Stop-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
                        }
                    }
                } catch { Write-Warning 'Cannot enumerate emulator child processes for cleanup.' }
                $process.Refresh()
                if (-not $process.HasExited) { Stop-Process -Id $process.Id }
                throw
            }
            # A failed identity verification should leave a booted AVD available
            # for inspection; only a failed boot belongs to process cleanup.
            if ($MaskIdentity) { Invoke-IdentityMask }
        }
        'Status' {
            & $emulator -accel-check
            & $adb devices -l
            Write-Host "Selected lab: $AvdName / $serial"
        }
        'Stop' { Stop-LabDevice }
        'Identity' { Invoke-IdentityMask }
        'AntiVM' {
            Assert-LabDevice
            if (-not (Test-LabReady)) { throw 'Android is not ready. Run -Action Start first.' }
            if (-not $selectedProfilePath) { throw 'Anti-VM on this API requires an explicit -ProfilePath.' }
            $env:GOCACHE = [IO.Path]::GetFullPath((Join-Path $projectRoot '.test-go-cache'))
            $env:GOTMPDIR = [IO.Path]::GetFullPath((Join-Path $projectRoot '.test-tmp'))
            New-Item -ItemType Directory -Force -Path $env:GOTMPDIR | Out-Null
            $binary = Join-Path $labRoot 'antivm.exe'
            Push-Location $projectRoot
            try {
                & go build -o $binary ./cmd/antivm
                if ($LASTEXITCODE -ne 0) { throw 'Anti-VM build failed.' }
            } finally { Pop-Location }
            $runRoot = Join-Path $labRoot ('antivm-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
            $results = @()
            # Run separately: a critical identity failure must not hide battery results.
            foreach ($module in @('identity', 'environment', 'battery', 'display')) {
                $moduleRoot = Join-Path $runRoot $module
                New-Item -ItemType Directory -Force -Path $moduleRoot | Out-Null
                & $binary session start --profile $selectedProfilePath --adb $adb --serial $serial `
                    --module $module --sessions $moduleRoot --report json |
                    Set-Content -LiteralPath (Join-Path $moduleRoot 'result.json') -Encoding utf8
                $code = $LASTEXITCODE
                $reportText = [string](Get-Content -Raw -LiteralPath (Join-Path $moduleRoot 'result.json'))
                if (-not $reportText.Trim()) { throw "Anti-VM $module did not produce a report (exit $code)." }
                $report = $reportText | ConvertFrom-Json
                $results += [pscustomobject]@{ Module = $module; Status = $report.status; ExitCode = $code }
                $sessionDir = Get-ChildItem -LiteralPath $moduleRoot -Directory | Sort-Object Name | Select-Object -Last 1
                if ($sessionDir) {
                    & $binary session diff --session $sessionDir.FullName --format json `
                        --out (Join-Path $moduleRoot 'diff.json')
                    if ($LASTEXITCODE -ne 0) { throw "Cannot compare $module device states." }
                }
            }
            $results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runRoot 'summary.json') -Encoding utf8
            $results | Format-Table -AutoSize
            Write-Host "Evidence: $runRoot"
        }
    }
} finally {
    foreach ($name in $savedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process')
    }
}
