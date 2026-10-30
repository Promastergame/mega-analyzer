#!/usr/bin/env bash
# lab-down.sh — stop everything lab-up.sh started.
set -u
LABDATA=/root/mega-analyzer-main/labs/servers/.rundata

echo "Stopping lab servers..."
pkill -f "$LABDATA/bin/" 2>/dev/null
pkill -f "manage.py runserver 127.0.0.1:180" 2>/dev/null
pkill -f "trackercollector/cmd" 2>/dev/null
pkill -f "labs-trackercollector" 2>/dev/null
pkill -f "$LABDATA/bin/trackercollector" 2>/dev/null

echo "Stopping databases..."
pkill -f "postgres -D $LABDATA/pg" 2>/dev/null
pkill -f "mariadbd --no-defaults --datadir=$LABDATA/mysql" 2>/dev/null

sleep 2
echo "Done. Remaining lab ports still listening (should be none):"
for p in 55432 33306 18099 18001 18002 18003 18004 18005 18006 18007 18008 18009 18010 18011 18111; do
  (echo >"/dev/tcp/127.0.0.1/$p") 2>/dev/null && echo "  $p STILL UP"
done
echo "(no lines above = all stopped)"
