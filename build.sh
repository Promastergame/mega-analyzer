#!/usr/bin/env sh
# ==============================================================================
#  Mega-Analyzer build script
#
#  Targets Linux, macOS, Android/Termux and Arch Linux ARM (aarch64 / armv7).
#  Run  ./build.sh --help  for all options.
# ==============================================================================
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_root"

# ── Defaults ──────────────────────────────────────────────────────────────────
BUILD_MODE=auto          # auto | core | gnn | full
OUT_DIR=bin
BIN_NAME=analyzer
VERSION=${VERSION:-$(cat "$project_root/VERSION")}
STRIP=1
STATIC=0
CLEAN=0
VERBOSE=0
RUN_AFTER=0
EXTRA_TAGS=""
JOBS=""
GOOS_OVERRIDE=""
GOARCH_OVERRIDE=""
GOARM_OVERRIDE=""

RED=""; GRN=""; YLW=""; BLU=""; DIM=""; RST=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED="$(printf '\033[31m')"; GRN="$(printf '\033[32m')"; YLW="$(printf '\033[33m')"
    BLU="$(printf '\033[34m')"; DIM="$(printf '\033[2m')"; RST="$(printf '\033[0m')"
fi

info()  { printf '%s==>%s %s\n' "$BLU" "$RST" "$*"; }
ok()    { printf '%s  ok%s %s\n' "$GRN" "$RST" "$*"; }
warn()  { printf '%swarn%s %s\n' "$YLW" "$RST" "$*" >&2; }
die()   { printf '%serr %s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
dbg()   { [ "$VERBOSE" -eq 1 ] && printf '%s     %s%s\n' "$DIM" "$*" "$RST" || true; }

usage() {
    cat <<'EOF'
Mega-Analyzer build script

USAGE
  ./build.sh [options]

BUILD MODE
  --core              Pure-Go build, CGO disabled. No Rust/Zig needed.
                      This is the default on Android/Termux and on any host
                      without a working cargo + C toolchain.
  --gnn               Core + Rust GNN classifier (needs cargo and cgo).
  --full, --native    Core + GNN + OmniSec native FFI engines.
  --tags "a,b"        Append extra Go build tags.
  --auto              Pick the best mode for this host (default).

TARGET
  --os <goos>         Override GOOS      (linux, android, darwin, windows...)
  --arch <goarch>     Override GOARCH    (arm64, arm, amd64, 386...)
  --goarm <5|6|7>     ARM version for 32-bit ARM builds (default: 7)
  --android           Shorthand for a Termux/Android arm64 build.
  --armv7             Shorthand for 32-bit ARMv7 (Arch Linux ARM / older phones).
  --static            Fully static binary (CGO off, netgo+osusergo).

OUTPUT
  -o, --out <dir>     Output directory            (default: bin)
  --name <file>       Output binary name          (default: analyzer)
  --version <ver>     Version stamped into binary (default: 1.0.0-beta.1)
  --no-strip          Keep symbols and DWARF (debug builds).

MISC
  -j, --jobs <n>      Parallel compile jobs (sets GOMAXPROCS and cargo -j).
  --clean             Remove previous build output first.
  --run               Launch the web UI after a successful build.
  -v, --verbose       Verbose output.
  -h, --help          Show this help.

ENVIRONMENT
  VERSION, CC, GOOS, GOARCH, GOARM, GOFLAGS are all respected.

EXAMPLES
  ./build.sh                          # auto-detect best mode for this device
  ./build.sh --core                   # guaranteed-portable pure Go build
  ./build.sh --android --static       # static arm64 binary for Termux
  ./build.sh --armv7 --core           # 32-bit Arch Linux ARM
  ./build.sh --full -j 4              # everything, 4 jobs
  ./build.sh --core --run             # build then open the web UI
EOF
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --core)            BUILD_MODE=core ;;
        --gnn)             BUILD_MODE=gnn ;;
        --full|--native)   BUILD_MODE=full ;;
        --auto)            BUILD_MODE=auto ;;
        --tags)            [ $# -ge 2 ] || die "--tags needs a value"; EXTRA_TAGS="$2"; shift ;;
        --os)              [ $# -ge 2 ] || die "--os needs a value"; GOOS_OVERRIDE="$2"; shift ;;
        --arch)            [ $# -ge 2 ] || die "--arch needs a value"; GOARCH_OVERRIDE="$2"; shift ;;
        --goarm)           [ $# -ge 2 ] || die "--goarm needs a value"; GOARM_OVERRIDE="$2"; shift ;;
        --android)         GOOS_OVERRIDE=android; GOARCH_OVERRIDE=arm64 ;;
        --armv7)           GOARCH_OVERRIDE=arm; GOARM_OVERRIDE=7 ;;
        --static)          STATIC=1 ;;
        -o|--out)          [ $# -ge 2 ] || die "--out needs a value"; OUT_DIR="$2"; shift ;;
        --name)            [ $# -ge 2 ] || die "--name needs a value"; BIN_NAME="$2"; shift ;;
        --version)         [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift ;;
        --no-strip)        STRIP=0 ;;
        -j|--jobs)         [ $# -ge 2 ] || die "--jobs needs a value"; JOBS="$2"; shift ;;
        --clean)           CLEAN=1 ;;
        --run)             RUN_AFTER=1 ;;
        -v|--verbose)      VERBOSE=1 ;;
        -h|--help)         usage; exit 0 ;;
        *)                 die "unknown option: $1  (try --help)" ;;
    esac
    shift
done

# ── Host / platform detection ─────────────────────────────────────────────────
host_os=$(uname -s 2>/dev/null || echo unknown)
host_arch=$(uname -m 2>/dev/null || echo unknown)

IS_TERMUX=0
case "${PREFIX:-}" in *com.termux*) IS_TERMUX=1 ;; esac
[ -d /data/data/com.termux/files/usr ] && IS_TERMUX=1
[ "${TERMUX_VERSION:-}" != "" ] && IS_TERMUX=1

IS_ARCHARM=0
if [ -f /etc/arch-release ]; then
    case "$host_arch" in aarch64|armv7l|armv8l|armv6l) IS_ARCHARM=1 ;; esac
fi

# Map uname -m onto GOARCH.
guess_goarch=""
guess_goarm=""
case "$host_arch" in
    aarch64|arm64)        guess_goarch=arm64 ;;
    armv8l|armv7l|armv7)  guess_goarch=arm; guess_goarm=7 ;;
    armv6l|armv6)         guess_goarch=arm; guess_goarm=6 ;;
    x86_64|amd64)         guess_goarch=amd64 ;;
    i686|i386)            guess_goarch=386 ;;
    riscv64)              guess_goarch=riscv64 ;;
esac

TARGET_GOOS=${GOOS_OVERRIDE:-${GOOS:-}}
TARGET_GOARCH=${GOARCH_OVERRIDE:-${GOARCH:-$guess_goarch}}
TARGET_GOARM=${GOARM_OVERRIDE:-${GOARM:-$guess_goarm}}
[ "$TARGET_GOARCH" = arm ] && [ -z "$TARGET_GOARM" ] && TARGET_GOARM=7

platform_label="$host_os/$host_arch"
[ "$IS_TERMUX" -eq 1 ] && platform_label="$platform_label (Android/Termux)"
[ "$IS_ARCHARM" -eq 1 ] && platform_label="$platform_label (Arch Linux ARM)"
info "Host: $platform_label"

# Termux needs a writable TMPDIR; the default /tmp does not exist there.
if [ "$IS_TERMUX" -eq 1 ] && [ -z "${TMPDIR:-}" ]; then
    TMPDIR="${PREFIX:-/data/data/com.termux/files/usr}/tmp"
    mkdir -p "$TMPDIR"
    export TMPDIR
    dbg "TMPDIR=$TMPDIR"
fi

# ── Toolchain checks ──────────────────────────────────────────────────────────
command -v go >/dev/null 2>&1 || die "Go toolchain not found in PATH.
  Termux:         pkg install golang
  Arch Linux ARM: pacman -S go"

have_cargo=0
command -v cargo >/dev/null 2>&1 && have_cargo=1

have_cc=0
if [ -n "${CC:-}" ]; then
    have_cc=1
elif command -v cc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
    have_cc=1
fi

# Termux ships clang, not cc. Point CGO at it so cgo builds do not fail.
if [ "$IS_TERMUX" -eq 1 ] && [ -z "${CC:-}" ] && command -v clang >/dev/null 2>&1; then
    CC=clang
    export CC
    dbg "CC=clang (Termux)"
fi

cross=0
if [ -n "$TARGET_GOOS" ] && [ "$TARGET_GOOS" != "$(go env GOHOSTOS)" ]; then cross=1; fi
if [ -n "$TARGET_GOARCH" ] && [ "$TARGET_GOARCH" != "$(go env GOHOSTARCH)" ]; then cross=1; fi

# ── Resolve build mode ────────────────────────────────────────────────────────
if [ "$BUILD_MODE" = auto ]; then
    if [ "$STATIC" -eq 1 ] || [ "$cross" -eq 1 ]; then
        BUILD_MODE=core
        dbg "auto -> core (static or cross build)"
    elif [ "$IS_TERMUX" -eq 1 ]; then
        BUILD_MODE=core
        dbg "auto -> core (Termux: Rust cdylib support is unreliable)"
    elif [ "$have_cargo" -eq 1 ] && [ "$have_cc" -eq 1 ]; then
        BUILD_MODE=gnn
        dbg "auto -> gnn (cargo + C toolchain present)"
    else
        BUILD_MODE=core
        dbg "auto -> core (no cargo and/or no C compiler)"
    fi
fi

# Downgrade gracefully instead of failing outright.
if [ "$BUILD_MODE" != core ]; then
    if [ "$have_cargo" -eq 0 ]; then
        warn "cargo not found - falling back to --core."
        warn "  Termux: pkg install rust   |   Arch ARM: pacman -S rust"
        BUILD_MODE=core
    elif [ "$have_cc" -eq 0 ]; then
        warn "no C compiler for cgo - falling back to --core."
        warn "  Termux: pkg install clang  |   Arch ARM: pacman -S base-devel"
        BUILD_MODE=core
    elif [ "$STATIC" -eq 1 ]; then
        warn "--static forces CGO off - falling back to --core."
        BUILD_MODE=core
    fi
fi

# ── Assemble tags / flags ─────────────────────────────────────────────────────
tags=""
case "$BUILD_MODE" in
    core) tags="" ;;
    gnn)  tags="omnisec_ml_gnn" ;;
    full) tags="omnisec_ml_gnn,omnisec_rust_ffi" ;;
esac
if [ -n "$EXTRA_TAGS" ]; then
    [ -n "$tags" ] && tags="$tags,$EXTRA_TAGS" || tags="$EXTRA_TAGS"
fi
if [ "$STATIC" -eq 1 ]; then
    [ -n "$tags" ] && tags="$tags,netgo,osusergo" || tags="netgo,osusergo"
fi

build_date=$(date +%Y-%m-%d 2>/dev/null || echo unknown)
commit=unknown
if command -v git >/dev/null 2>&1 && [ -d .git ]; then
    commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
fi

ldflags="-X main.Version=$VERSION -X main.BuildDate=$build_date -X main.CommitHash=$commit"
[ "$STRIP" -eq 1 ] && ldflags="-s -w $ldflags"
[ "$STATIC" -eq 1 ] && ldflags="$ldflags -extldflags '-static'"

if [ "$BUILD_MODE" = core ]; then
    CGO_ENABLED=0
else
    CGO_ENABLED=1
fi
export CGO_ENABLED

[ -n "$TARGET_GOOS" ]   && { GOOS=$TARGET_GOOS;     export GOOS; }
[ -n "$TARGET_GOARCH" ] && { GOARCH=$TARGET_GOARCH; export GOARCH; }
if [ "$TARGET_GOARCH" = arm ] && [ -n "$TARGET_GOARM" ]; then
    GOARM=$TARGET_GOARM
    export GOARM
fi
if [ -n "$JOBS" ]; then
    GOMAXPROCS=$JOBS
    export GOMAXPROCS
fi

# Low-RAM phones OOM during linking; keep the Go build cache on disk.
if [ "$IS_TERMUX" -eq 1 ]; then
    GOFLAGS="${GOFLAGS:-} -p=${JOBS:-2}"
    export GOFLAGS
    dbg "GOFLAGS=$GOFLAGS"
fi

# ── Clean ─────────────────────────────────────────────────────────────────────
if [ "$CLEAN" -eq 1 ]; then
    info "Cleaning $OUT_DIR and Go build cache"
    rm -rf "$OUT_DIR"
    go clean -cache >/dev/null 2>&1 || true
    [ "$have_cargo" -eq 1 ] && [ -d rust/target ] && rm -rf rust/target || true
fi

mkdir -p "$OUT_DIR"

target_desc="${GOOS:-$(go env GOHOSTOS)}/${GOARCH:-$(go env GOHOSTARCH)}"
[ "${GOARM:-}" != "" ] && target_desc="$target_desc (GOARM=$GOARM)"
info "Mode: $BUILD_MODE   Target: $target_desc   CGO_ENABLED=$CGO_ENABLED"
[ -n "$tags" ] && dbg "tags: $tags"

# ── Step 1: Rust GNN library (only when needed) ───────────────────────────────
step=1
total=2
[ "$BUILD_MODE" != core ] && total=3

gnn_library=""
if [ "$BUILD_MODE" != core ]; then
    info "[$step/$total] Building Rust GNN library"
    cargo_args="--manifest-path rust/Cargo.toml --release -p omnisec-ml-gnn"
    [ -n "$JOBS" ] && cargo_args="$cargo_args -j $JOBS"
    [ "$VERBOSE" -eq 1 ] || cargo_args="$cargo_args --quiet"
    # shellcheck disable=SC2086
    cargo build $cargo_args

    case "$host_os" in
        Darwin) gnn_library='libomnisec_ml_gnn.dylib'; gnn_rpath='-Wl,-rpath,@executable_path' ;;
        *)      gnn_library='libomnisec_ml_gnn.so';    gnn_rpath='-Wl,-rpath,$ORIGIN' ;;
    esac
    CGO_LDFLAGS="$gnn_rpath"
    export CGO_LDFLAGS
    step=$((step + 1))
fi

# ── Step 2: Go binary ─────────────────────────────────────────────────────────
info "[$step/$total] Building $BIN_NAME"
set -- -trimpath -ldflags "$ldflags" -o "$OUT_DIR/$BIN_NAME"
[ -n "$tags" ] && set -- -tags "$tags" "$@"
[ "$VERBOSE" -eq 1 ] && set -- -v "$@"
go build "$@" ./pkg/cmd/analyzer
step=$((step + 1))

# ── Step 3: Copy runtime library ──────────────────────────────────────────────
if [ "$BUILD_MODE" != core ]; then
    info "[$step/$total] Copying GNN runtime library"
    gnn_source="rust/target/release/$gnn_library"
    [ -f "$gnn_source" ] || die "GNN runtime library was not produced: $gnn_source"
    cp "$gnn_source" "$OUT_DIR/"
fi

chmod +x "$OUT_DIR/$BIN_NAME" 2>/dev/null || true

size=$(ls -lh "$OUT_DIR/$BIN_NAME" 2>/dev/null | awk '{print $5}' || echo '?')
ok "Built $project_root/$OUT_DIR/$BIN_NAME  ($size, $BUILD_MODE)"

if [ "$BUILD_MODE" = core ]; then
    printf '%s     Pure Go build - no shared libraries required at runtime.%s\n' "$DIM" "$RST"
else
    printf '%s     Keep %s next to the binary (or on LD_LIBRARY_PATH).%s\n' "$DIM" "$gnn_library" "$RST"
fi

if [ "$RUN_AFTER" -eq 1 ]; then
    if [ "$cross" -eq 1 ]; then
        warn "--run skipped: cross-compiled binary cannot run on this host."
    else
        info "Starting web UI"
        exec "$project_root/run.sh" --web
    fi
fi
