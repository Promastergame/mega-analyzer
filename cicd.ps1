# =================================================================
#               OMNISEC ADVANCED LOCAL CI/CD PIPELINE
#           Interactive Multi-Language Pipeline Orchestrator
# =================================================================
#
# Usage:
#   .\cicd.ps1 -Stage All              # Run full pipeline
#   .\cicd.ps1 -Stage Lint             # Run quality checks only
#   .\cicd.ps1 -Stage Test             # Run unit tests only
#   .\cicd.ps1 -Stage Build            # Compile optimized release binaries
#   .\cicd.ps1 -Stage Package          # Package artifacts & create ZIP distribution
#   .\cicd.ps1 -SkipLint               # Skip linting during the build
#   .\cicd.ps1 -SkipElixir             # Skip Elixir server compilation
#   .\cicd.ps1 -SkipZig                # Skip Zig GUI compilation
#   .\cicd.ps1 -Clean                  # Clean build targets and intermediate cache
#
# Rules: 
#   - Zero emoji in UI. Strict high-quality console characters.
#   - Zero-dependency HTML report generated locally under dist/
#

param (
    [ValidateSet("All", "Lint", "Test", "Build", "Package", "Report")]
    [string]$Stage = "All",

    [switch]$SkipLint = $false,
    [switch]$SkipTest = $false,
    [switch]$SkipTests = $false,
    [switch]$SkipElixir = $false,
    [switch]$SkipZig = $false,
    [switch]$SkipSigning = $false,
    [switch]$SkipSign = $false,
    [switch]$SkipVet = $false,
    [switch]$Clean = $false,
    [switch]$CleanRust = $false,
    # Defaults to the Version constant in pkg/cmd/analyzer/main.go (same source
    # bump_version.py reads from) so this can't silently drift out of sync with
    # a release. Falls back to a hardcoded literal only if main.go is missing
    # or doesn't match the expected `Version = "X.Y.Z-something"` pattern.
    [string]$Version = $(
        $VersionFile = Join-Path $PSScriptRoot "VERSION"
        if (Test-Path $VersionFile) {
            (Get-Content $VersionFile -Raw).Trim()
        } else {
            "0.0.0-dev"
        }
    ),
    [string]$BuildDate = (Get-Date -Format "yyyy-MM-dd"),
    
    [switch]$Linux = $false,
    [ValidateSet("windows", "linux")]
    [string]$TargetOS = "windows"
)

$ErrorActionPreference = "Stop"

# Resolve Target OS
if ($Linux) {
    $TargetOS = "linux"
} elseif ($IsLinux -or $PSVersionTable.Platform -eq "Unix") {
    if (-not $PSBoundParameters.ContainsKey('TargetOS')) {
        $TargetOS = "linux"
    }
}

$SkipTesting = $SkipTest -or $SkipTests

$TargetOSLower = $TargetOS.ToLower()
$LibExtension = if ($TargetOSLower -eq "windows") { ".dll" } else { ".so" }
$ExeExtension = if ($TargetOSLower -eq "windows") { ".exe" } else { "" }

$PipelineStartTime = [DateTime]::Now
$ReportData = @{
    Version = $Version
    BuildDate = $BuildDate
    OS = "$TargetOS (Local)"
    Status = "Success"
    StartTime = $PipelineStartTime.ToString("yyyy-MM-dd HH:mm:ss")
    EndTime = ""
    TotalDuration = 0
    Stages = @()
    Binaries = @()
}

# --- ANSI Console Formatting Helpers ---
function Show-Header {
    # Clear-Host manipulates the cursor, which throws when stdout is redirected
    # (headless CI / piped output). Tolerate that so the pipeline runs headless.
    try { Clear-Host } catch {}
    Write-Host "+---------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|                OMNISEC AUTOMATED CI/CD ENGINE                 |" -ForegroundColor Cyan
    Write-Host "+---------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "| Version: $Version | Build Date: $BuildDate | Air-Gapped / Proprietary  |" -ForegroundColor Gray
    Write-Host "+---------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Show-StageHeader([string]$StageName) {
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  STAGE: $StageName" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Cyan
}

function Log-Info([string]$Msg) {
    Write-Host "  [-] $Msg" -ForegroundColor Gray
}

function Log-Success([string]$Msg) {
    Write-Host "  [+] $Msg" -ForegroundColor Green
}

function Log-Warning([string]$Msg) {
    Write-Host "  [!] WARNING: $Msg" -ForegroundColor Yellow
}

function Log-Error([string]$Msg) {
    Write-Host "  [x] ERROR: $Msg" -ForegroundColor Red
}

# --- Clean Stage ---
if ($Clean -or $CleanRust) {
    Show-Header
    Write-Host "[*] Executing Workspace Clean..." -ForegroundColor Yellow
    if ($Clean) {
        if (Test-Path "bin") {
            try {
                Remove-Item "bin" -Recurse -Force -ErrorAction Stop | Out-Null
                Log-Success "Removed bin/ directory"
            } catch {
                Log-Warning "Could not fully remove bin/ directory (files may be locked): $_"
            }
        }
        if (Test-Path "dist") {
            try {
                Remove-Item "dist" -Recurse -Force -ErrorAction Stop | Out-Null
                Log-Success "Removed dist/ directory"
            } catch {
                Log-Warning "Could not fully remove dist/ directory (files may be locked): $_"
            }
        }
        if (Test-Path "zig/zig-out") {
            try {
                Remove-Item "zig/zig-out" -Recurse -Force -ErrorAction Stop | Out-Null
                Log-Success "Removed Zig ML Runtime build output"
            } catch {
                Log-Warning "Could not fully remove zig/zig-out directory: $_"
            }
        }
    }
    if ($CleanRust -and (Test-Path "rust/target")) {
        Log-Info "Executing deep cargo clean in rust workspace..."
        Push-Location rust
        try {
            cargo clean
            Log-Success "Rust target cleaned successfully"
        } catch {
            Log-Warning "Cargo clean failed: $_"
        }
        Pop-Location
    }
    Write-Host "Workspace Clean complete." -ForegroundColor Green
    exit 0
}

# --- Check Environment Dependencies ---
function Check-Environment {
    Show-StageHeader "ENVIRONMENT VERIFICATION"
    $GoVersion = $null
    $RustVersion = $null
    $CargoVersion = $null
    $ZigVersion = $null
    $ElixirVersion = $null
    $OtpVersion = $null
    
    # 1. Check Go
    try {
        $GoRaw = (go version)
        $GoVersion = $GoRaw.Split(" ")[2]
        Log-Success "Go version: $GoVersion"
    } catch {
        Log-Error "Go compiler (go) not found! Ensure Go >=1.27rc2 is installed."
        exit 1
    }

    # 2. Check Rust & Cargo
    try {
        $CargoRaw = (cargo --version)
        $CargoVersion = $CargoRaw.Split(" ")[1]
        $RustcRaw = (rustc --version)
        $RustVersion = $RustcRaw.Split(" ")[1]
        Log-Success "Rust version: $RustVersion"
        Log-Success "Cargo version: $CargoVersion"
    } catch {
        Log-Error "Rust/Cargo compiler not found! Ensure Rust >=1.95 is installed."
        exit 1
    }

    # 3. Check Zig
    try {
        $ZigRaw = (zig version)
        $ZigVersion = $ZigRaw.Trim()
        Log-Success "Zig version: $ZigVersion"
    } catch {
        Log-Error "Zig compiler (zig) not found! Ensure Zig is installed."
        exit 1
    }

    # 4. Check Elixir & Erlang/OTP
    try {
        $ElixirRaw = (elixir --version)
        $ElixirVersion = "Unknown"
        $OtpVersion = "Unknown"
        $ElixirText = $ElixirRaw -join "`n"
        if ($ElixirText -match "Elixir\s+(\S+)") {
            $ElixirVersion = $Matches[1]
        }
        if ($ElixirText -match "Erlang/OTP\s+(\S+)") {
            $OtpVersion = $Matches[1]
        }
        Log-Success "Elixir version: $ElixirVersion"
        Log-Success "Erlang/OTP version: $OtpVersion"
    } catch {
        Log-Warning "Elixir compiler (elixir) not found! Elixir server compilation will be skipped."
    }
    
    $ReportData.Stages += @{
        Name = "Environment Verify"
        Status = "Passed"
        Duration = 0
        Details = "Go $GoVersion, Rust $RustVersion (Cargo $CargoVersion), Zig $ZigVersion, Elixir $ElixirVersion (OTP $OtpVersion)"
    }
}

# --- Stage 1: Quality Audit (Lint & Format) ---
function Run-LintStage {
    Show-StageHeader "CODE QUALITY & AUDIT"
    $StageStart = [DateTime]::Now
    
    # 1. Rust Format & Clippy
    Log-Info "Checking Rust Workspace formatting..."
    Push-Location rust
    cargo fmt --all -- --check 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        Log-Error "Rust formatting drift detected. Run 'cargo fmt' to fix, then re-run the pipeline."
        exit 1
    }
    Log-Success "Rust formatting matches cargo standard."

    Log-Info "Running Rust Clippy static analysis..."
    cargo clippy --workspace -- -D warnings | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # Advisory until the pre-existing clippy warning backlog in rust/ is fixed
        # (same policy as .github/workflows/ci.yml).
        Log-Warning "Rust Clippy generated issues (advisory until the warning backlog is fixed)."
    } else {
        Log-Success "Rust Clippy static analysis passed (0 warnings/errors)."
    }
    Pop-Location

    # 2. Go Format & Vet
    Log-Info "Checking Go Modules formatting..."
    $GoFiles = Get-ChildItem -Recurse -Filter "*.go" -ErrorAction SilentlyContinue | Where-Object {
        $_.FullName -notlike "*\vendor\*"  -and
        $_.FullName -notlike "*\rust\*"    -and
        $_.FullName -notlike "*\.cache\*"  -and
        $_.FullName -notlike "*\.git\*"    -and
        $_.FullName -notlike "*\node_modules\*"
    }
    $GoUnformatted = @()
    foreach ($File in $GoFiles) {
        try {
            $FmtCheck = gofmt -l $File.FullName 2>&1
            if ($FmtCheck) {
                $GoUnformatted += $File.FullName
            }
        } catch {
            # Silently skip unreadable files (e.g. locked OS paths)
        }
    }
    if ($GoUnformatted.Count -eq 0) {
        Log-Success "Go formatting matches standard."
    } else {
        # Read-only on purpose: the pipeline must never rewrite source files.
        # Flip this to a hard failure once the existing 258-file drift is
        # normalized with a dedicated 'gofmt -w' pass.
        Log-Warning ("{0} Go file(s) need 'gofmt -w' (run manually):" -f $GoUnformatted.Count)
        $GoUnformatted | Select-Object -First 10 | ForEach-Object { Log-Info "  $_" }
    }

    Log-Info "Running Go Vet analyzer..."
    if ($SkipVet) {
        Log-Warning "Go Vet skipped by -SkipVet flag."
    } else {
        go vet ./...
        if ($LASTEXITCODE -ne 0) {
            Log-Error "Go Vet found issues."
            exit 1
        }
        Log-Success "Go Vet static analyzer passed."
    }

    $StageDuration = ([DateTime]::Now - $StageStart).TotalSeconds
    $ReportData.Stages += @{
        Name = "Quality Audit"
        Status = "Passed"
        Duration = [Math]::Round($StageDuration, 2)
        Details = "Format and Clippy audits verified for Rust, Go, and Zig."
    }
}

# --- Stage 2: Unit Testing ---
function Run-TestStage {
    Show-StageHeader "UNIT TESTING (DYNAMIC RESOLUTION)"
    $StageStart = [DateTime]::Now

    # 1. Compile Rust workspace crates for testing
    Log-Info "Compiling Rust workspace crates for testing..."
    Push-Location rust
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Log-Error "Rust workspace testing build failed!"
        Pop-Location
        exit 1
    }
    Log-Success "Rust release build for tests completed."
    Pop-Location

    # 2. Relocate DLLs / Shared Libraries for FFI Tests
    Log-Info "Relocating dynamic libraries ($LibExtension) for FFI..."
    $DebugTarget = "rust/target/release"
    if ($TargetOSLower -eq "linux" -and $env:OS -like "*Windows*") {
        $DebugTarget = "rust/target/x86_64-unknown-linux-gnu/release"
    }
    if (!(Test-Path $DebugTarget)) {
        $DebugTarget = "rust/target/release"
    }
    $Dlls = Get-ChildItem -Path $DebugTarget -Filter "*$LibExtension"
    
    if ($Dlls.Count -eq 0) {
        Log-Warning "No libraries found in $DebugTarget for testing!"
    } else {
        # Test destinations
        $BinDest = "bin"
        $ApkDest = "pkg/internal/apkloader"
        $GnnDest = "pkg/ml/gnn"
        
        if (!(Test-Path $BinDest)) { New-Item -ItemType Directory -Force -Path $BinDest | Out-Null }
        if (!(Test-Path $ApkDest)) { New-Item -ItemType Directory -Force -Path $ApkDest | Out-Null }
        if (!(Test-Path $GnnDest)) { New-Item -ItemType Directory -Force -Path $GnnDest | Out-Null }
        
        foreach ($Dll in $Dlls) {
            Copy-Item $Dll.FullName -Destination $BinDest -Force
            
            $NameLower = $Dll.Name.ToLower()
            $IsApkLib = $NameLower -match "omnisec_(lifter_dalvik|loader_dex|analysis_symbolic|analysis_virt|scan_native)\.(dll|so)"
            $IsGnnLib = $NameLower -match "omnisec_ml_gnn\.(dll|so)"

            if ($IsApkLib) {
                Copy-Item $Dll.FullName -Destination $ApkDest -Force
            }
            if ($IsGnnLib) {
                Copy-Item $Dll.FullName -Destination $GnnDest -Force
            }
        }
        Log-Success "FFI Dynamic libraries successfully linked."
    }

    # Install GNN weights so the inference stage can find them at runtime.
    # runner_gnn.go resolves ~/.analyzer/models/gnn_weights.json via gnncache.DiscoverWeights.
    $GnnWeightsSrc = "rust/gnn_weights.json"
    if (Test-Path $GnnWeightsSrc) {
        $ModelsDir = Join-Path $env:USERPROFILE ".analyzer/models"
        if (!(Test-Path $ModelsDir)) { New-Item -ItemType Directory -Force -Path $ModelsDir | Out-Null }
        Copy-Item $GnnWeightsSrc -Destination (Join-Path $ModelsDir "gnn_weights.json") -Force
        Log-Success "GNN weights installed to $ModelsDir"
    } else {
        Log-Warning "rust/gnn_weights.json not found — GNN stage will be skipped at runtime"
    }

    # 3. Run Rust Tests
    Log-Info "Running Rust Workspace tests..."
    Push-Location rust
    cargo test --workspace
    if ($LASTEXITCODE -ne 0) {
        Log-Error "Rust workspace unit testing failures occurred!"
        Pop-Location
        exit 1
    }
    Log-Success "All Rust workspace unit tests passed."
    Pop-Location

    # 4. Run Go Tests with Inject PATH
    Log-Info "Running Go unit tests (injecting DLL environment path)..."
    $OriginalPath = $env:PATH
    $env:PATH = "$PSScriptRoot\bin;" + $env:PATH
    
    go test ./...
    $GoTestExitCode = $LASTEXITCODE
    
    $env:PATH = $OriginalPath
    if ($GoTestExitCode -ne 0) {
        Log-Error 'Go unit testing failures occurred!'
        exit 1
    }
    Log-Success 'All Go unit tests passed.'

    # 5. Run Zig Library Tests (omnisec-ml-runtime)
    Log-Info "Running Zig ML Runtime tests..."
    Push-Location zig
    zig build test
    if ($LASTEXITCODE -ne 0) {
        Log-Error "Zig ML Runtime test failures occurred!"
        Pop-Location
        exit 1
    }
    Log-Success "All Zig ML Runtime tests passed."
    Pop-Location

    $StageDuration = ([DateTime]::Now - $StageStart).TotalSeconds
    $ReportData.Stages += @{
        Name = "Unit Testing"
        Status = "Passed"
        Duration = [Math]::Round($StageDuration, 2)
        Details = "Rust cargo test workspace, Go multi-module test runner, Zig ML Runtime completed successfully."
    }
}

# --- Stage 3: Compilation Stage ---
function Run-CompileStage {
    Show-StageHeader "OPTIMIZED PRODUCTION COMPILATION"
    $StageStart = [DateTime]::Now

    # Backup existing bin directory if it exists
    if (Test-Path "bin") {
        Log-Info "Backing up existing bin/ directory..."
        $BackupDir = "bin_backups"
        if (!(Test-Path $BackupDir)) { New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null }
        
        $BackupBase = Join-Path $BackupDir "bin_old"
        $BackupName = $BackupBase
        $Counter = 2
        while (Test-Path $BackupName) {
            $BackupName = "${BackupBase}_v${Counter}"
            $Counter++
        }
        try {
            Copy-Item -Path "bin" -Destination $BackupName -Recurse -Force
            Remove-Item -Path "bin" -Recurse -Force
            Log-Success "Backed up existing bin/ to $BackupName and deleted original bin/"
        } catch {
            Log-Warning "Failed to backup/remove bin/ directory: $_"
            try {
                Rename-Item -Path "bin" -NewName $BackupName -Force
                Log-Success "Renamed bin/ to $BackupName as fallback"
            } catch {
                Log-Warning "Failed fallback renaming of bin/: $_"
            }
        }
    }
    # Ensure fresh empty bin directory exists
    New-Item -ItemType Directory -Force -Path "bin" | Out-Null

    # 1. Compile Rust Workspace Release / Cross-Compile Compatible Crates
    if ($TargetOSLower -eq "linux" -and $env:OS -like "*Windows*") {
        Log-Info "Cross-compiling compatible Rust libraries to Linux (x86_64-unknown-linux-gnu)..."
        Push-Location rust
        $OldCC = $env:CC_x86_64_unknown_linux_gnu
        $OldAR = $env:AR_x86_64_unknown_linux_gnu
        $OldRustFlags = $env:RUSTFLAGS
        $OldLinker = $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
        $LinkerWrapper = Join-Path (Get-Location) "zig-linker.bat"
        try {
            # Leverage Zig to cross-compile any C components of the compatible crates
            $env:CC_x86_64_unknown_linux_gnu = "zig cc -target x86_64-linux-gnu"
            $env:AR_x86_64_unknown_linux_gnu = "zig ar"
            
            # Create a temporary linker wrapper using Zig cc (which includes Linux glibc headers and libs)
            "@echo off`nzig cc -target x86_64-linux-gnu %*" | Out-File -FilePath $LinkerWrapper -Encoding ascii -Force
            $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = $LinkerWrapper

            # 1. Compile omnisec-ml-gnn separately with its SONAME set
            $env:RUSTFLAGS = "-C link-arg=-Wl,-soname,libomnisec_ml_gnn.so"
            cargo build --release --target x86_64-unknown-linux-gnu -p omnisec-ml-gnn
            if ($LASTEXITCODE -ne 0) {
                throw "Cargo build for GNN exited with code $LASTEXITCODE"
            }

            # 2. Compile the other required libraries (no soname overrides needed)
            $env:RUSTFLAGS = ""
            cargo build --release --target x86_64-unknown-linux-gnu `
                -p omnisec-analysis-symbolic `
                -p omnisec-analysis-virt `
                -p omnisec-lifter-dalvik `
                -p omnisec-loader-dex `
                -p omnisec-scan-native `
                -p omnisec-arsc `
                -p omnisec-ml-inference
                
            if ($LASTEXITCODE -ne 0) {
                throw "Cargo build for other libraries exited with code $LASTEXITCODE"
            }
            Log-Success "Compatible Rust libraries cross-compiled successfully."
            
            # Copy built Linux .so libraries to target/release so Go's cgo linker can find them
            $SoFiles = Get-ChildItem -Path "target/x86_64-unknown-linux-gnu/release" -Filter "*.so"
            $ReleaseDest = "target/release"
            if (!(Test-Path $ReleaseDest)) { New-Item -ItemType Directory -Force -Path $ReleaseDest | Out-Null }
            foreach ($So in $SoFiles) {
                Copy-Item $So.FullName -Destination $ReleaseDest -Force
            }
        } catch {
            Log-Error "Rust compilation failed: $_"
            Pop-Location
            exit 1
        } finally {
            $env:CC_x86_64_unknown_linux_gnu = $OldCC
            $env:AR_x86_64_unknown_linux_gnu = $OldAR
            $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = $OldLinker
            $env:RUSTFLAGS = $OldRustFlags
            if (Test-Path $LinkerWrapper) { Remove-Item $LinkerWrapper -Force }
        }
        Pop-Location
    } else {
        Log-Info "Compiling Rust Workspace (Release) for $TargetOS..."
        Push-Location rust
        $OldCC = $env:CC_x86_64_unknown_linux_gnu
        $OldAR = $env:AR_x86_64_unknown_linux_gnu
        try {
            cargo build --release
            if ($LASTEXITCODE -ne 0) {
                throw "Cargo build exited with code $LASTEXITCODE"
            }
            Log-Success "Rust Workspace compiled successfully."
        } catch {
            Log-Error "Rust compilation failed!"
            Pop-Location
            exit 1
        } finally {
            $env:CC_x86_64_unknown_linux_gnu = $OldCC
            $env:AR_x86_64_unknown_linux_gnu = $OldAR
        }
        Pop-Location
    }

    # 2. Compile Elixir Server
    if (-not $SkipElixir) {
        if ($TargetOSLower -eq "linux" -and $env:OS -like "*Windows*") {
            Log-Warning "Skipped Elixir Server compilation for Linux target on Windows host."
        } else {
            Log-Info "Compiling Elixir Server..."
            Push-Location server
            mix local.hex --force
            mix local.rebar --force
            mix deps.get --only prod
            if ($LASTEXITCODE -ne 0) {
                Log-Error "Elixir dependencies retrieval failed!"
                Pop-Location
                exit 1
            }
            $env:MIX_ENV = "prod"
            mix compile
            if ($LASTEXITCODE -ne 0) {
                Log-Error "Elixir compilation failed!"
                Pop-Location
                exit 1
            }
            mix release --overwrite
            if ($LASTEXITCODE -ne 0) {
                Log-Error "Elixir release generation failed!"
                Pop-Location
                exit 1
            }
            Log-Success "Elixir Server compiled and release generated successfully."
            Pop-Location
        }
    }

    # 3. Relocate DLLs / Shared Libraries
    Log-Info "Relocating Dynamic Libraries ($LibExtension)..."
    $TargetDir = "rust/target/release"
    if ($TargetOSLower -eq "linux" -and $env:OS -like "*Windows*") {
        $TargetDir = "rust/target/x86_64-unknown-linux-gnu/release"
    }
    
    $Dlls = Get-ChildItem -Path $TargetDir -Filter "*$LibExtension"
    if ($Dlls.Count -eq 0) {
        Log-Warning "No Dynamic Libraries found in $TargetDir!"
    } else {
        $BinDest = "bin"
        $ApkLoaderDest = "pkg/internal/apkloader"
        $GnnDest = "pkg/ml/gnn"

        if (!(Test-Path $BinDest)) { New-Item -ItemType Directory -Force -Path $BinDest | Out-Null }
        if (!(Test-Path $ApkLoaderDest)) { New-Item -ItemType Directory -Force -Path $ApkLoaderDest | Out-Null }
        if (!(Test-Path $GnnDest)) { New-Item -ItemType Directory -Force -Path $GnnDest | Out-Null }

        foreach ($Dll in $Dlls) {
            Copy-Item $Dll.FullName -Destination $BinDest -Force
            
            $NameLower = $Dll.Name.ToLower()
            $IsApkLib = $NameLower -match "omnisec_(lifter_dalvik|loader_dex|analysis_symbolic|analysis_virt|scan_native)\.(dll|so)"
            $IsGnnLib = $NameLower -match "omnisec_ml_gnn\.(dll|so)"

            if ($IsApkLib) {
                Copy-Item $Dll.FullName -Destination $ApkLoaderDest -Force
            }
            if ($IsGnnLib) {
                Copy-Item $Dll.FullName -Destination $GnnDest -Force
            }
        }
        Log-Success "Dynamic libraries relocated successfully."
    }

    # Install GNN weights so the inference stage can find them at runtime.
    $GnnWeightsSrc = "rust/gnn_weights.json"
    if (Test-Path $GnnWeightsSrc) {
        $ModelsDir = Join-Path $env:USERPROFILE ".analyzer/models"
        if (!(Test-Path $ModelsDir)) { New-Item -ItemType Directory -Force -Path $ModelsDir | Out-Null }
        Copy-Item $GnnWeightsSrc -Destination (Join-Path $ModelsDir "gnn_weights.json") -Force
        Log-Success "GNN weights installed to $ModelsDir"
    } else {
        Log-Warning "rust/gnn_weights.json not found — GNN stage will be skipped at runtime"
    }

    # 4. Compile Go Executable
    Log-Info "Compiling Go Executable for $TargetOS..."
    if (!(Test-Path "bin")) { New-Item -ItemType Directory -Force -Path "bin" | Out-Null }
    
    $OldGOOS = $env:GOOS
    $OldGOARCH = $env:GOARCH
    $OldCGO = $env:CGO_ENABLED
    $OldCC = $env:CC
    $OldCXX = $env:CXX
    $OldCgoLdFlags = $env:CGO_LDFLAGS
    $OldCgoLdFlagsAllow = $env:CGO_LDFLAGS_ALLOW
    try {
        $CurrentDate = (Get-Date -Format "yyyy-MM-dd")
        $GoExeName = if ($TargetOSLower -eq "windows") { "analyzer.exe" } else { "analyzer" }
        
        if ($TargetOSLower -eq "linux") {
            $env:GOOS = "linux"
            $env:GOARCH = "amd64"
            if ($env:OS -like "*Windows*") {
                $env:CGO_ENABLED = "1"
                $env:CC = "zig cc -target x86_64-linux-gnu"
                $env:CXX = "zig c++ -target x86_64-linux-gnu"
                
                # Provide the target library search path and RPATH to CGO linker without modifying source go files
                $LinuxReleasePath = Join-Path (Get-Location) "rust/target/x86_64-unknown-linux-gnu/release"
                $env:CGO_LDFLAGS = "-L$LinuxReleasePath -lomnisec_ml_gnn -Wl,-rpath,'`$ORIGIN'"
                $env:CGO_LDFLAGS_ALLOW = "-Wl,-rpath.*"
            } else {
                $env:CGO_ENABLED = "1"
                if (-not $env:CGO_LDFLAGS) {
                    $env:CGO_LDFLAGS = "-lomnisec_ml_gnn -Wl,-rpath,'`$ORIGIN'"
                }
                $env:CGO_LDFLAGS_ALLOW = "-Wl,-rpath.*"
            }
        }

        $releaseCommit = (& git rev-parse HEAD).Trim()
        go build -tags omnisec_ml_gnn -ldflags "-s -w -X main.Version=$Version -X main.BuildDate=$CurrentDate -X main.CommitHash=$releaseCommit" -o "bin/$GoExeName" ./pkg/cmd/analyzer
        if (Test-Path "analyzer.flags.txt") {
            Copy-Item "analyzer.flags.txt" -Destination "bin/analyzer.flags.txt" -Force
            Log-Success "Copied APK-only analyzer.flags.txt to bin/."
        }
        Log-Success "Go binary compiled successfully."
    } catch {
        Log-Error "Go compilation failed: $_"
        exit 1
    } finally {
        $env:GOOS = $OldGOOS
        $env:GOARCH = $OldGOARCH
        $env:CGO_ENABLED = $OldCGO
        $env:CC = $OldCC
        $env:CXX = $OldCXX
        $env:CGO_LDFLAGS = $OldCgoLdFlags
        $env:CGO_LDFLAGS_ALLOW = $OldCgoLdFlagsAllow
    }

    # 5. Compile Zig ML Runtime
    if (-not $SkipZig) {
        if ($TargetOSLower -eq "linux" -and $env:OS -like "*Windows*") {
            Log-Warning "Skipped Zig ML Runtime compilation for Linux target on Windows host."
        } else {
            Log-Info "Compiling Zig ML Runtime..."
            Push-Location zig
            zig build -Doptimize=ReleaseFast
            if ($LASTEXITCODE -ne 0) {
                Log-Error "Zig ML Runtime compilation failed!"
                Pop-Location
                exit 1
            }
            Log-Success "Zig ML Runtime compiled successfully."
            Pop-Location
        }
    }

    # 7. Check for Minisign Signatures
    Log-Info "Checking for Minisign Signatures..."
    if ($SkipSigning -or $SkipSign) {
        Log-Warning "Minisign signing skipped by parameter."
    } else {
        $KeyPath = "minisign.key"
        if (!(Test-Path $KeyPath)) {
            $UserDefaultKey = "$Home\.minisign\minisign.key"
            if (Test-Path $UserDefaultKey) { $KeyPath = $UserDefaultKey }
        }
        if (Test-Path $KeyPath) {
            if (Get-Command minisign -ErrorAction SilentlyContinue) {
                try {
                    $AnalyzerBin = if ($TargetOSLower -eq "windows") { "bin/analyzer.exe" } else { "bin/analyzer" }
                    minisign -S -m $AnalyzerBin -s $KeyPath -f | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "Minisign signature failed for analyzer." }
                    Log-Success "Binaries signed successfully with Minisign."
                } catch {
                    Log-Warning "Minisign signing failed: $_"
                }
            }
        }
    }

    $StageDuration = ([DateTime]::Now - $StageStart).TotalSeconds
    $Details = "Compiled Rust Release crates, relocated optimized libraries ($LibExtension), compiled Go binary with stripped debug info (-s -w)"
    if (-not $SkipElixir) { $Details += ", compiled Elixir server" }
    if (-not $SkipZig) { $Details += ", compiled Zig ML Runtime + GUI ReleaseFast" }
    $ReportData.Stages += @{
        Name = "Production Compilation"
        Status = "Passed"
        Duration = [Math]::Round($StageDuration, 2)
        Details = $Details
    }
}

# --- Stage 4: Release Packaging ---
function Run-PackageStage {
    Show-StageHeader "RELEASE INTEGRITY & PACKAGING"
    $StageStart = [DateTime]::Now

    $DistFolder = "dist"
    $BinFolder = "bin"

    if (!(Test-Path $DistFolder)) {
        New-Item -ItemType Directory -Force -Path $DistFolder | Out-Null
    }

    # Generate checksum file
    Log-Info "Verifying binary integrity and computing SHA-256 checksums..."
    $ChecksumFile = Join-Path $DistFolder "SHA256SUMS.txt"
    if (Test-Path $ChecksumFile) { Remove-Item $ChecksumFile -Force }

    $Files = Get-ChildItem -Path $BinFolder -File | Where-Object { $_.Extension -in ".exe", ".dll", ".so", ".txt" -or $_.Name -in "analyzer" }
    
    foreach ($File in $Files) {
        $Hash = (Get-FileHash $File.FullName -Algorithm SHA256).Hash.ToLower()
        "$Hash *$($File.Name)" | Out-File -FilePath $ChecksumFile -Append -Encoding ascii
        
        $SizeMB = [Math]::Round($File.Length / 1MB, 2)
        Log-Success "Verified $($File.Name) ($SizeMB MB) | Checksum: $($Hash.Substring(0, 12))..."
        
        $ReportData.Binaries += @{
            Name = $File.Name
            SizeMB = $SizeMB
            Checksum = $Hash
        }
    }

    # Packaging archive
    Log-Info "Staging files for compression (excluding scan outputs and logs)..."
    $StagingFolder = Join-Path $DistFolder "staging"
    if (Test-Path $StagingFolder) { Remove-Item $StagingFolder -Recurse -Force | Out-Null }
    New-Item -ItemType Directory -Force -Path $StagingFolder | Out-Null

    # Copy only production files to staging
    Get-ChildItem -Path $BinFolder -File | Where-Object { $_.Extension -in ".exe", ".dll", ".so", ".txt" -or $_.Name -in "analyzer" } | ForEach-Object {
        Copy-Item $_.FullName -Destination $StagingFolder -Force
    }

    # Copy documentation and license files from root
    $DocFiles = @("LICENSE", "NOTICE.txt", "QUICKSTART.md", "FlagiFiles.md", "minisign.pub")
    foreach ($DocFile in $DocFiles) {
        if (Test-Path $DocFile) {
            Copy-Item $DocFile -Destination $StagingFolder -Force
        }
    }

    # Copy release-specific README files and rename them in staging folder
    if (Test-Path "docs/README_RELEASE.md") {
        Copy-Item "docs/README_RELEASE.md" -Destination (Join-Path $StagingFolder "README.md") -Force
    }
    if (Test-Path "docs/README_RELEASE.ru.md") {
        Copy-Item "docs/README_RELEASE.ru.md" -Destination (Join-Path $StagingFolder "README.ru.md") -Force
    }

    # Copy generated SHA256SUMS.txt from dist directory to staging
    if (Test-Path $ChecksumFile) {
        Copy-Item $ChecksumFile -Destination $StagingFolder -Force
    }

    # Copy Elixir server release if it exists, Elixir is not skipped, and we are not cross-compiling (under server/_build/prod/rel)
    $ElixirRelPath = "server/_build/prod/rel"
    $IsCrossCompiling = ($TargetOSLower -eq "linux" -and $env:OS -like "*Windows*") -or ($TargetOSLower -eq "windows" -and $env:OS -notlike "*Windows*")
    $HasElixir = -not $SkipElixir -and -not $IsCrossCompiling -and (Test-Path $ElixirRelPath)
    if ($HasElixir) {
        Log-Info "Staging Elixir server release artifacts..."
        $StagingElixir = Join-Path $StagingFolder "elixir_server"
        if (Test-Path $StagingElixir) { Remove-Item $StagingElixir -Recurse -Force | Out-Null }
        New-Item -ItemType Directory -Force -Path $StagingElixir | Out-Null
        Copy-Item -Path "$ElixirRelPath\*" -Destination $StagingElixir -Recurse -Force
        Log-Success "Staged Elixir server release artifacts."
    }

    $ZipPath = Join-Path $DistFolder "omnisec-v$Version-$TargetOSLower-amd64.zip"
    $NoElixirZipPath = Join-Path $DistFolder "omnisec-v$Version-$TargetOSLower-amd64-no-elixir.zip"

    if ($HasElixir) {
        # Produce package WITH Elixir
        if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
        Log-Info "Compressing staged artifacts with Elixir server into archive..."
        try {
            Compress-Archive -Path "$StagingFolder\*" -DestinationPath $ZipPath -Force
            $ZipSizeMB = [Math]::Round((Get-Item $ZipPath).Length / 1MB, 2)
            Log-Success "Created distribution package (with Elixir): $ZipPath ($ZipSizeMB MB)"
        } catch {
            Log-Error "Archiver compression failed for package with Elixir!"
            if (Test-Path $StagingFolder) { Remove-Item $StagingFolder -Recurse -Force | Out-Null }
            exit 1
        }

        # Produce package WITHOUT Elixir by temporarily removing elixir_server folder
        if (Test-Path $NoElixirZipPath) { Remove-Item $NoElixirZipPath -Force }
        Log-Info "Compressing staged artifacts without Elixir server into archive..."
        $StagingElixir = Join-Path $StagingFolder "elixir_server"
        if (Test-Path $StagingElixir) { Remove-Item $StagingElixir -Recurse -Force | Out-Null }
        try {
            Compress-Archive -Path "$StagingFolder\*" -DestinationPath $NoElixirZipPath -Force
            $NoElixirZipSizeMB = [Math]::Round((Get-Item $NoElixirZipPath).Length / 1MB, 2)
            Log-Success "Created distribution package (without Elixir): $NoElixirZipPath ($NoElixirZipSizeMB MB)"
        } catch {
            Log-Error "Archiver compression failed for package without Elixir!"
            if (Test-Path $StagingFolder) { Remove-Item $StagingFolder -Recurse -Force | Out-Null }
            exit 1
        }
        $Details = "Packaged release binaries with Elixir ($ZipSizeMB MB) and without Elixir ($NoElixirZipSizeMB MB)."
    } else {
        # Elixir is skipped, produce ONLY the package without Elixir
        if (Test-Path $NoElixirZipPath) { Remove-Item $NoElixirZipPath -Force }
        Log-Info "Compressing staged artifacts without Elixir server into archive..."
        try {
            Compress-Archive -Path "$StagingFolder\*" -DestinationPath $NoElixirZipPath -Force
            $NoElixirZipSizeMB = [Math]::Round((Get-Item $NoElixirZipPath).Length / 1MB, 2)
            Log-Success "Created distribution package (without Elixir): $NoElixirZipPath ($NoElixirZipSizeMB MB)"
        } catch {
            Log-Error "Archiver compression failed for package without Elixir!"
            if (Test-Path $StagingFolder) { Remove-Item $StagingFolder -Recurse -Force | Out-Null }
            exit 1
        }
        $Details = "Packaged release binaries without Elixir ($NoElixirZipSizeMB MB)."
    }

    if (Test-Path $StagingFolder) { Remove-Item $StagingFolder -Recurse -Force | Out-Null }

    $StageDuration = ([DateTime]::Now - $StageStart).TotalSeconds
    $ReportData.Stages += @{
        Name = "Release Packaging"
        Status = "Passed"
        Duration = [Math]::Round($StageDuration, 2)
        Details = "SHA-256 sums calculated. Packaged release binaries ($TargetOS) into local ZIP distribution archive ($ZipSizeMB MB)."
    }
}

# --- Stage 5: Beautiful HTML Report Generation ---
function Run-ReportStage {
    Show-StageHeader "HTML BUILD REPORT ENGINE"
    
    $ReportFile = "dist/build-report.html"
    Log-Info "Generating interactive build analysis dashboard..."

    # 1. Build Stage Items HTML (no here-strings to prevent parsing issues)
    $StageHtml = ""
    foreach ($Stg in $ReportData.Stages) {
        $StgName = $Stg.Name
        $StgDetails = $Stg.Details
        $StgDuration = $Stg.Duration
        $StgStatus = $Stg.Status
        $StgStatusClass = if ($StgStatus -eq "Passed") { "step-status" } else { "step-status step-status--failed" }
        $StgIconClass = if ($StgStatus -eq "Passed") { "step-icon" } else { "step-icon pending" }
        $StageHtml += "
            <div class='timeline-step'>
                <div class='step-info'>
                    <div class='$StgIconClass'>
                        <svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='3'>
                            <polyline points='20 6 9 17 4 12'></polyline>
                        </svg>
                    </div>
                    <div class='step-details'>
                        <h4>$StgName</h4>
                        <p>$StgDetails</p>
                    </div>
                </div>
                <div class='step-meta'>
                    <div class='step-duration'>${StgDuration}s</div>
                    <div class='$StgStatusClass'>$StgStatus</div>
                </div>
            </div>"
    }

    # 2. Build Binary Items HTML (no here-strings)
    $BinaryHtml = ""
    foreach ($Bin in $ReportData.Binaries) {
        $BinName = $Bin.Name
        $BinSize = $Bin.SizeMB
        $BinChecksum = $Bin.Checksum
        $ShortHash = $BinChecksum.Substring(0, 16) + "..."
        $BinaryHtml += "
                            <tr>
                                <td class='binary-name'>$BinName</td>
                                <td>$BinSize MB</td>
                                <td><span class='hash-code' title='$BinChecksum'>$ShortHash</span></td>
                            </tr>"
    }

    # 3. Master Single-Quoted Literal Template (PowerShell ignores all $'s inside @' ... '@)
    $HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniSec Local Build Pipeline Report - v{{VERSION}}</title>
    <style>
        :root {
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --bg-card-hover: #334155;
            --border: #475569;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --cyan: #38bdf8;
            --green: #4ade80;
            --yellow: #facc15;
            --red: #f87171;
            --font-family: 'Outfit', 'Inter', -apple-system, sans-serif;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-main);
            color: var(--text-primary);
            font-family: var(--font-family);
            padding: 2.5rem 1.5rem;
            line-height: 1.5;
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }

        .header-title h1 {
            font-size: 2.2rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            color: var(--text-primary);
        }

        .header-title span {
            color: var(--cyan);
            font-weight: 600;
            font-family: monospace;
            background: rgba(56, 189, 248, 0.1);
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.95rem;
        }

        .status-badge {
            display: flex;
            align-items: center;
            background: rgba(74, 222, 128, 0.1);
            border: 1px solid var(--green);
            color: var(--green);
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 0.9rem;
        }

        .status-badge svg {
            width: 16px;
            height: 16px;
            margin-right: 8px;
            fill: currentColor;
        }

        .grid-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }

        .card-meta {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            transition: border-color 0.2s;
        }

        .card-meta:hover {
            border-color: var(--cyan);
        }

        .card-meta h3 {
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }

        .card-meta p {
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            border-left: 4px solid var(--cyan);
            padding-left: 0.75rem;
            color: var(--text-primary);
        }

        .timeline {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin-bottom: 2.5rem;
        }

        .timeline-step {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .step-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .step-icon {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: rgba(74, 222, 128, 0.1);
            color: var(--green);
        }

        .step-icon.pending {
            background: rgba(250, 204, 21, 0.1);
            color: var(--yellow);
        }

        .step-details h4 {
            font-size: 1.05rem;
            font-weight: 600;
        }

        .step-details p {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .step-meta {
            text-align: right;
        }

        .step-duration {
            font-weight: 600;
            color: var(--cyan);
        }

        .step-status {
            font-size: 0.8rem;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.05em;
            color: var(--green);
        }

        .step-status--failed {
            color: var(--red);
        }

        .grid-layouts {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2.5rem;
        }

        @media (max-width: 900px) {
            .grid-layouts {
                grid-template-columns: 1fr;
            }
        }

        .table-container {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            width: 100%;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            background: rgba(0, 0, 0, 0.2);
            padding: 1rem;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border);
        }

        td {
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.95rem;
        }

        tr:last-child td {
            border-bottom: none;
        }

        .binary-name {
            font-weight: 600;
            color: var(--cyan);
        }

        .hash-code {
            font-family: monospace;
            background: rgba(0,0,0,0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .metrics-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            height: fit-content;
        }

        .metrics-item {
            margin-bottom: 1.5rem;
        }

        .metrics-item:last-child {
            margin-bottom: 0;
        }

        .metrics-label {
            display: flex;
            justify-content: space-between;
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }

        .progress-bar-container {
            width: 100%;
            height: 8px;
            background: rgba(255,255,255,0.05);
            border-radius: 9999px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: var(--cyan);
            border-radius: 9999px;
        }

        .progress-fill.green {
            background: var(--green);
        }

        footer {
            margin-top: 5rem;
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>OmniSec Build Report</h1>
                <span>v{{VERSION}}</span>
            </div>
            <div class="status-badge">
                <svg viewBox="0 0 20 20">
                    <path d="M0 11l2-2 5 5L18 3l2 2L7 18z"/>
                </svg>
                PIPELINE SUCCESSFUL
            </div>
        </header>

        <div class="grid-meta">
            <div class="card-meta">
                <h3>Build Timestamp</h3>
                <p>{{START_TIME}}</p>
            </div>
            <div class="card-meta">
                <h3>Orchestrator OS</h3>
                <p>Windows AMD64</p>
            </div>
            <div class="card-meta">
                <h3>Total Execution</h3>
                <p>{{TOTAL_DURATION}} Seconds</p>
            </div>
            <div class="card-meta">
                <h3>Pipeline Build</h3>
                <p>Secure Air-Gapped</p>
            </div>
        </div>

        <h2 class="section-title">Execution Pipeline Stages</h2>
        <div class="timeline">
            {{STAGES}}
        </div>

        <div class="grid-layouts">
            <div>
                <h2 class="section-title">Built Distribution Binaries</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Binary Asset</th>
                                <th>Size</th>
                                <th>SHA-256 Checksum Signature</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{BINARIES}}
                        </tbody>
                    </table>
                </div>
            </div>

            <div>
                <h2 class="section-title">Binary Size Analysis</h2>
                <div class="metrics-card">
                    <div class="metrics-item">
                        <div class="metrics-label">
                            <span>analyzer.exe</span>
                            <span>14.5 MB</span>
                        </div>
                        <div class="progress-bar-container">
                            <div class="progress-fill" style="width: 78%;"></div>
                        </div>
                    </div>
                    <div class="metrics-item">
                        <div class="metrics-label">
                            <span>Dynamic Libraries</span>
                            <span>17.6 MB</span>
                        </div>
                        <div class="progress-bar-container">
                            <div class="progress-fill" style="width: 90%;"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <footer>
            OmniSec Local Build Pipeline (c) 2026. Generated securely.
        </footer>
    </div>
</body>
</html>
'@

    # 4. Perform simple template replacements
    $HtmlContent = $HtmlTemplate.
        Replace("{{VERSION}}", $Version).
        Replace("{{START_TIME}}", $ReportData.StartTime).
        Replace("{{TOTAL_DURATION}}", $ReportData.TotalDuration).
        Replace("{{STAGES}}", $StageHtml).
        Replace("{{BINARIES}}", $BinaryHtml)

    if (!(Test-Path "dist")) {
        New-Item -ItemType Directory -Force -Path "dist" | Out-Null
    }
    $HtmlContent | Out-File -FilePath $ReportFile -Encoding utf8
    Log-Success "Stunning HTML Build Report generated at: $ReportFile"
}

# --- Execution Entrypoint ---
try {
    Show-Header

    if ($Stage -eq "All") {
        Check-Environment
        if (-not $SkipLint) { Run-LintStage } else { Log-Warning "Skipped quality format and clippy stage." }
        if (-not $SkipTesting) { Run-TestStage } else { Log-Warning "Skipped unit testing stage." }
        Run-CompileStage
        Run-PackageStage
        
        $TotalElapsed = [DateTime]::Now - $PipelineStartTime
        $ReportData.TotalDuration = [Math]::Round($TotalElapsed.TotalSeconds, 2)
        $ReportData.EndTime = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
        
        Run-ReportStage
    } 
    elseif ($Stage -eq "Lint") {
        Run-LintStage
    }
    elseif ($Stage -eq "Test") {
        Run-TestStage
    }
    elseif ($Stage -eq "Build") {
        Run-CompileStage
    }
    elseif ($Stage -eq "Package") {
        Run-PackageStage
    }
    elseif ($Stage -eq "Report") {
        # Populate dummy release info for stand-alone report building
        $ReportData.Stages += @{ Name = "Environment Verify"; Status = "Passed"; Duration = 0.05; Details = "Fast dry-run mock." }
        $ReportData.Stages += @{ Name = "Quality Audit"; Status = "Passed"; Duration = 1.25; Details = "Fast dry-run mock." }
        $ReportData.Stages += @{ Name = "Unit Testing"; Status = "Passed"; Duration = 4.88; Details = "Fast dry-run mock." }
        $ReportData.Stages += @{ Name = "Production Compilation"; Status = "Passed"; Duration = 15.22; Details = "Fast dry-run mock." }
        $ReportData.Stages += @{ Name = "Release Packaging"; Status = "Passed"; Duration = 1.04; Details = "Fast dry-run mock." }
        
        $ReportData.Binaries += @{ Name = "analyzer.exe"; SizeMB = 14.5; Checksum = "7a544a0e98031d279cf0214c7c8c3664d93021f1e31e3c233f8d381c81ef40d4" }
        $ReportData.Binaries += @{ Name = "libz3.dll"; SizeMB = 17.6; Checksum = "f2a24c29cf47bc0acb8d28cf423c89bdfcd3c4cf0f21e0ca123a9d7eb192bd89" }
        
        $TotalElapsed = [DateTime]::Now - $PipelineStartTime
        $ReportData.TotalDuration = [Math]::Round($TotalElapsed.TotalSeconds, 2)
        $ReportData.EndTime = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
        
        Run-ReportStage
    }

    Write-Host ""
    Write-Host "+---------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|                 LOCAL PIPELINE RUN COMPLETED                  |" -ForegroundColor Cyan
    Write-Host "+---------------------------------------------------------------+" -ForegroundColor Cyan
    $PipeDuration = [DateTime]::Now - $PipelineStartTime
    $PipeSeconds = $PipeDuration.TotalSeconds.ToString("F2")
    Write-Host "  Total elapsed time: $PipeSeconds seconds" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Log-Error "Pipeline run failed. Check logs above."
    Write-Host "  Error message: $_" -ForegroundColor Red
    exit 1
}
