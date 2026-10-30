#!/usr/bin/env sh
# ==============================================================================
#  Mega-Analyzer launcher
#
#  Finds the analyzer binary, sets up the runtime library path, and forwards
#  every remaining argument to it. Knows about Android/Termux and Arch Linux ARM.
#  Run  ./run.sh --help  for launcher options.
# ==============================================================================
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

WEB=0
PORT=""
HOST=""
OPEN_BROWSER=1
BIN_OVERRIDE=""
LIB_DIRS=""
VERBOSE=0

RED=""; GRN=""; YLW=""; BLU=""; DIM=""; RST=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED="$(printf '\033[31m')"; GRN="$(printf '\033[32m')"; YLW="$(printf '\033[33m')"
    BLU="$(printf '\033[34m')"; DIM="$(printf '\033[2m')"; RST="$(printf '\033[0m')"
fi
info() { printf '%s==>%s %s\n' "$BLU" "$RST" "$*"; }
warn() { printf '%swarn%s %s\n' "$YLW" "$RST" "$*" >&2; }
die()  { printf '%serr %s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
dbg()  { [ "$VERBOSE" -eq 1 ] && printf '%s     %s%s\n' "$DIM" "$*" "$RST" || true; }

usage() {
    cat <<'EOF'
Mega-Analyzer launcher

USAGE
  ./run.sh [launcher options] [-- ] [analyzer arguments...]

LAUNCHER OPTIONS
  -w, --web            Start the local web UI.
  -p, --port <n>       Web UI port (default: 7474).
      --host <addr>    Bind address. Use 0.0.0.0 to reach the UI from another
                       device on the same Wi-Fi (phone, tablet, laptop).
      --lan            Shorthand for --host 0.0.0.0.
  -n, --no-browser     Do not auto-open a browser.
      --bin <path>     Use a specific analyzer binary.
      --lib <dir>      Extra directory to add to the library search path.
  -v, --verbose        Verbose launcher output.
  -h, --help           This help. Use --analyzer-help for the analyzer's own help.
      --analyzer-help  Show the analyzer CLI help.

Everything not listed above is passed straight through to the analyzer, so
all normal flags keep working:

  ./run.sh -t app.apk -o out
  ./run.sh --web --lan --port 8080
  ./run.sh -- -t app.apk -profile deep

NOTES
  * Android/Termux and Arch Linux ARM are detected automatically; TMPDIR and
    the shared-library path are configured for you.
  * On Termux the UI opens with termux-open-url when termux-api is installed;
    otherwise just open the printed URL in your browser.
EOF
}

# ── Parse launcher flags, collect the rest ────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        -w|--web)        WEB=1 ;;
        -p|--port)       [ $# -ge 2 ] || die "--port needs a value"; PORT="$2"; shift ;;
        --host)          [ $# -ge 2 ] || die "--host needs a value"; HOST="$2"; shift ;;
        --lan)           HOST=0.0.0.0 ;;
        -n|--no-browser) OPEN_BROWSER=0 ;;
        --bin)           [ $# -ge 2 ] || die "--bin needs a value"; BIN_OVERRIDE="$2"; shift ;;
        --lib)           [ $# -ge 2 ] || die "--lib needs a value"; LIB_DIRS="${LIB_DIRS:+$LIB_DIRS:}$2"; shift ;;
        -v|--verbose)    VERBOSE=1 ;;
        -h|--help)       usage; exit 0 ;;
        --analyzer-help) set -- --help; break ;;
        --)              shift; break ;;
        *)               break ;;
    esac
    shift
done
# Remaining "$@" is forwarded verbatim to the analyzer.

# ── Platform detection ────────────────────────────────────────────────────────
host_arch=$(uname -m 2>/dev/null || echo unknown)

IS_TERMUX=0
case "${PREFIX:-}" in *com.termux*) IS_TERMUX=1 ;; esac
[ -d /data/data/com.termux/files/usr ] && IS_TERMUX=1
[ "${TERMUX_VERSION:-}" != "" ] && IS_TERMUX=1

IS_ARCHARM=0
if [ -f /etc/arch-release ]; then
    case "$host_arch" in aarch64|armv7l|armv8l|armv6l) IS_ARCHARM=1 ;; esac
fi

[ "$IS_TERMUX" -eq 1 ]  && dbg "platform: Android/Termux ($host_arch)"
[ "$IS_ARCHARM" -eq 1 ] && dbg "platform: Arch Linux ARM ($host_arch)"

# Termux has no /tmp; the analyzer needs a writable temp dir for uploads.
if [ "$IS_TERMUX" -eq 1 ] && [ -z "${TMPDIR:-}" ]; then
    TMPDIR="${PREFIX:-/data/data/com.termux/files/usr}/tmp"
    mkdir -p "$TMPDIR"
    export TMPDIR
    dbg "TMPDIR=$TMPDIR"
fi

# ── Locate the binary ───────────────────────────────────────────────────────
BIN=""
if [ -n "$BIN_OVERRIDE" ]; then
    [ -x "$BIN_OVERRIDE" ] || die "not executable: $BIN_OVERRIDE"
    BIN=$BIN_OVERRIDE
else
    for cand in \
        "$script_dir/bin/analyzer" \
        "$script_dir/analyzer" \
        "$script_dir/bin/analyzer.exe" \
        "$script_dir/analyzer.exe"
    do
        if [ -x "$cand" ]; then BIN=$cand; break; fi
    done
fi

if [ -z "$BIN" ]; then
    die "analyzer binary not found.
  Build it first:  ./build.sh          (auto-detects the best mode)
                   ./build.sh --core   (pure Go, works everywhere)
  Or point at one: ./run.sh --bin /path/to/analyzer"
fi
dbg "binary: $BIN"

# ── Library search path ──────────────────────────────────────────────────────
bin_dir=$(CDPATH= cd -- "$(dirname -- "$BIN")" && pwd)
LD_LIBRARY_PATH="$bin_dir:$script_dir${LIB_DIRS:+:$LIB_DIRS}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
if [ "$(uname -s 2>/dev/null || echo)" = "Darwin" ]; then
    DYLD_LIBRARY_PATH="$LD_LIBRARY_PATH"
    export DYLD_LIBRARY_PATH
fi
dbg "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"

# ── Web UI wiring ────────────────────────────────────────────────────────────
if [ -n "$HOST" ]; then
    MEGA_ANALYZER_HOST="$HOST"
    export MEGA_ANALYZER_HOST
fi

# Headless shells (Termux without termux-api, SSH, chroot) have no browser to
# open; auto-open would just print an error.
if [ "$OPEN_BROWSER" -eq 1 ] && [ "$WEB" -eq 1 ]; then
    if [ "$IS_TERMUX" -eq 1 ] && ! command -v termux-open-url >/dev/null 2>&1; then
        OPEN_BROWSER=0
        dbg "termux-open-url missing (pkg install termux-api) - not auto-opening"
    elif [ "$IS_TERMUX" -eq 0 ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ] \
         && [ "$(uname -s 2>/dev/null || echo)" != "Darwin" ]; then
        OPEN_BROWSER=0
        dbg "no DISPLAY/WAYLAND_DISPLAY - not auto-opening"
    fi
fi
if [ "$OPEN_BROWSER" -eq 0 ]; then
    MEGA_ANALYZER_NO_BROWSER=1
    export MEGA_ANALYZER_NO_BROWSER
fi

if [ "$WEB" -eq 1 ]; then
    # Build the argument list explicitly: a ${VAR:+...} expansion carrying a
    # quoted value splits inconsistently across shells.
    if [ -n "$PORT" ]; then
        set -- -web -web-port "$PORT" "$@"
    else
        set -- -web "$@"
    fi
    shown_host=${HOST:-127.0.0.1}
    shown_port=${PORT:-7474}
    info "Web UI: http://$shown_host:$shown_port"
    if [ "$shown_host" = "0.0.0.0" ]; then
        lan_ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
        [ -n "$lan_ip" ] && info "On this network: http://$lan_ip:$shown_port"
        warn "Bound to 0.0.0.0 - anyone on this network can reach the UI."
    fi
elif [ -n "$PORT" ]; then
    warn "--port has no effect without --web"
fi

dbg "exec: $BIN $*"
exec "$BIN" "$@"
