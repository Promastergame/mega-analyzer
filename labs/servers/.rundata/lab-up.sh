#!/usr/bin/env bash
# lab-up.sh — bring the whole intentionally-vulnerable lab up locally,
# WITHOUT Docker, on this Android/Termux-style host.
#
# Why this exists: this box's kernel has no System V IPC (shmget ->
# ENOSYS) and PostgreSQL/MariaDB refuse to run as root, so the normal
# `docker compose ... up` path from labs/servers/README.md can't be used
# here. This script works around both:
#   * runs the DB servers + Go servers under an unprivileged uid via setpriv
#   * LD_PRELOADs a tiny shim (shmshim.so) that emulates SysV shared memory
#     with file mmaps so PostgreSQL can start
#   * launches every process with `setsid ... </dev/null` so it fully
#     detaches from the controlling terminal and survives the shell/session
#     closing (otherwise a SIGHUP on session exit kills them all)
#
# ⚠️ Everything here is an intentionally vulnerable LOCAL lab. 127.0.0.1
# only. Never deploy. See labs/servers/README.md.
#
# Usage:  bash labs/servers/.rundata/lab-up.sh
# Stop:   bash labs/servers/.rundata/lab-down.sh
set -u

ROOT=/root/mega-analyzer-main/labs/servers
LABDATA="$ROOT/.rundata"
VENV="$ROOT/.venv/bin"
UID_UNPRIV=10322
SHIM="$LABDATA/shmshim.so"

mkdir -p /tmp/shmshim && chmod 777 /tmp/shmshim
mkdir -p "$LABDATA/bin"

up() { (echo >"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
wait_port() { for _ in $(seq 1 40); do up "$1" && return 0; sleep 1; done; return 1; }

# daemon <logfile> <command...> : fully detach from the terminal so the
# process survives this shell/session exiting.
daemon() {
  local log="$1"; shift
  setsid env "$@" >"$log" 2>&1 </dev/null &
}

echo "== PostgreSQL (:55432) =="
if up 55432; then echo "  already up"; else
  daemon "$LABDATA/pg.log" \
    LC_ALL=C LANG=C SHMSHIM_DIR=/tmp/shmshim LD_PRELOAD="$SHIM" \
    setpriv --reuid=$UID_UNPRIV --regid=$UID_UNPRIV --init-groups \
    postgres -D "$LABDATA/pg" -p 55432 -k "$LABDATA/pg" -c listen_addresses=127.0.0.1
  wait_port 55432 && echo "  up" || { echo "  FAILED"; tail -5 "$LABDATA/pg.log"; }
fi

echo "== MariaDB (:33306) =="
if up 33306; then echo "  already up"; else
  daemon "$LABDATA/mysqld.log" \
    LC_ALL=C LANG=C HOME="$LABDATA" \
    setpriv --reuid=$UID_UNPRIV --regid=$UID_UNPRIV --init-groups \
    mariadbd --no-defaults --datadir="$LABDATA/mysql" --port=33306 \
    --socket="$LABDATA/mysql/mysqld.sock" --bind-address=127.0.0.1 --skip-networking=0
  wait_port 33306 && echo "  up" || { echo "  FAILED"; tail -5 "$LABDATA/mysqld.log"; }
fi

echo "== trackercollector (:18099) =="
if up 18099; then echo "  already up"; else
  [ -x "$LABDATA/bin/trackercollector" ] || ( cd "$ROOT/trackercollector" && go build -o "$LABDATA/bin/trackercollector" ./cmd )
  daemon "$LABDATA/trackercollector.log" LISTEN_ADDR=127.0.0.1:18099 "$LABDATA/bin/trackercollector"
  wait_port 18099 && echo "  up" || echo "  FAILED"
fi

echo "== Go lab servers (Postgres-backed) =="
declare -A GO_PORT=( [admin-backdoor-header]=18001 [admin-jwt-none]=18002 [admin-idor-role]=18003 [sqli-login]=18004 [path-traversal-download]=18005 )
declare -A GO_DB=( [admin-backdoor-header]=labs_admin_backdoor_header [admin-jwt-none]=labs_admin_jwt_none [admin-idor-role]=labs_admin_idor_role [sqli-login]=labs_sqli_login [path-traversal-download]=labs_path_traversal )
for srv in admin-backdoor-header admin-jwt-none admin-idor-role sqli-login path-traversal-download; do
  p=${GO_PORT[$srv]}
  if up "$p"; then echo "  $srv already up (:$p)"; continue; fi
  [ -x "$LABDATA/bin/$srv" ] || ( cd "$ROOT/go/$srv" && go build -o "$LABDATA/bin/$srv" . )
  daemon "$LABDATA/$srv.log" \
    LISTEN_ADDR=127.0.0.1:$p \
    DATABASE_URL="postgres://labs:labs_lab_pw@127.0.0.1:55432/${GO_DB[$srv]}?sslmode=disable" \
    TRACKER_URL="http://127.0.0.1:18099/beacon/$srv" \
    DATA_DIR="$LABDATA/$srv-data" \
    "$LABDATA/bin/$srv"
  wait_port "$p" && echo "  $srv up (:$p)" || { echo "  $srv FAILED"; tail -3 "$LABDATA/$srv.log"; }
done

echo "== Coin injection shop (bbolt-backed, TCP :18011, UI :18111) =="
if up 18011 && up 18111; then echo "  coin-client-authoritative already up"; else
  mkdir -p "$LABDATA/coin-client-authoritative-data"
  [ -x "$LABDATA/bin/coin-client-authoritative" ] || (
    cd "$ROOT/go/coin-client-authoritative" && GOWORK=off go build -o "$LABDATA/bin/coin-client-authoritative" .
  )
  daemon "$LABDATA/coin-client-authoritative.log" \
    LISTEN_ADDR=127.0.0.1:18011 \
    HTTP_LISTEN_ADDR=127.0.0.1:18111 \
    DB_PATH="$LABDATA/coin-client-authoritative-data/coin-lab.db" \
    "$LABDATA/bin/coin-client-authoritative"
  wait_port 18011 && wait_port 18111 && echo "  coin shop up (:18011 / :18111)" || {
    echo "  coin shop FAILED"; tail -3 "$LABDATA/coin-client-authoritative.log";
  }
fi

echo "== Django lab servers (MariaDB-backed) =="
declare -A DJ_PORT=( [admin-hidden-debug]=18006 [sqli-raw]=18007 [insecure-deserialize]=18008 [csrf-cors-misconfig]=18009 [tracker-beacon]=18010 )
declare -A DJ_DB=( [admin-hidden-debug]=labs_admin_hidden_debug [sqli-raw]=labs_sqli_raw [insecure-deserialize]=labs_insecure_deserialize [csrf-cors-misconfig]=labs_csrf_cors [tracker-beacon]=labs_tracker_beacon )
for srv in admin-hidden-debug sqli-raw insecure-deserialize csrf-cors-misconfig tracker-beacon; do
  p=${DJ_PORT[$srv]}
  if up "$p"; then echo "  $srv already up (:$p)"; continue; fi
  daemon "$LABDATA/$srv.log" \
    DJANGO_CHDIR="$ROOT/django/$srv" \
    DB_HOST=127.0.0.1 DB_PORT=33306 DB_USER=labs DB_PASSWORD=labs_lab_pw DB_NAME=${DJ_DB[$srv]} \
    TRACKER_URL="http://127.0.0.1:18099/beacon/$srv" \
    bash -c "cd \"\$DJANGO_CHDIR\" && exec \"$VENV/python\" manage.py runserver 127.0.0.1:$p --noreload"
  wait_port "$p" && echo "  $srv up (:$p)" || { echo "  $srv FAILED"; tail -3 "$LABDATA/$srv.log"; }
done

echo
echo "Lab is up. All ports bound to 127.0.0.1 only. Processes are detached"
echo "(setsid) and survive this shell closing. Run the pipeline live tests with:"
echo "  cd /root/mega-analyzer-main && go test ./pkg/ncer/labtest/..."
