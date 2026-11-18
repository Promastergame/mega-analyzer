package modules

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/antivm/profile"
)

func thermalTemperatureCommand() string {
	// Enter init's mount namespace so the fixture is not confined to adbd.
	// Never disable SELinux: retain the observed sysfs label on fixture inodes.
	script := thermalTemperatureScript("/sys/class/thermal", "/data/local/tmp/mega-antivm/thermal")
	return "[ \"$(id -u)\" = 0 ] || { echo 'thermal fixture requires a root ADB shell' >&2; exit 1; }; " +
		"nsenter -t 1 -m -- /system/bin/sh -c " + quoteThermalShell(script)
}

func quoteThermalShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// Paths are parameters so shell integration tests can use a temporary fixture.
func thermalTemperatureScript(thermalRoot, fixtureRoot string) string {
	return fmt.Sprintf(`set -eu
thermal_root=%s
fixture_root=%s
expected=%d
target="$thermal_root/thermal_zone0/temp"
[ -d "$thermal_root" ] || { echo "thermal class is unavailable: $thermal_root" >&2; exit 1; }
# Repeated applications need neither another mount nor another overlay.
if [ -r "$target" ] && [ "$(cat "$target")" = "$expected" ]; then exit 0; fi
mkdir -p "$fixture_root"
chmod 755 "$fixture_root"
label_fixture() {
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = Enforcing ]; then
    context=${3:-}
    if [ -z "$context" ]; then context=$(ls -ZdL "$2" | awk '{print $1}'); fi
    case "$context" in u:object_r:*:s0) ;; *) echo "cannot read sysfs SELinux context" >&2; exit 1 ;; esac
    chcon -h "$context" "$1"
  fi
}
if [ -e "$target" ]; then
  source="$fixture_root/temp"
  printf '%%s\n' "$expected" > "$source"
  chmod 444 "$source"
  label_fixture "$source" "$target"
  mount --bind "$source" "$target"
else
  # sysfs cannot create a missing zone. Mirror existing class symlinks to
  # their absolute device targets, then bind a class containing the fixture.
  mirror=$(mktemp -d "$fixture_root/class.XXXXXX")
  chmod 755 "$mirror"
  for entry in "$thermal_root"/*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    name=${entry##*/}
    if [ "$name" = thermal_zone0 ]; then
      echo "thermal_zone0 exists without a temperature file" >&2; exit 1
    fi
    [ -L "$entry" ] || { echo "cannot preserve non-symlink thermal entry: $entry" >&2; exit 1; }
    resolved=$(readlink -f "$entry")
    case "$resolved" in "$thermal_root"|"$thermal_root"/*) echo "cannot preserve thermal symlink: $entry" >&2; exit 1 ;; esac
    ln -s "$resolved" "$mirror/$name"
    label_fixture "$mirror/$name" "$entry"
  done
  mkdir "$mirror/thermal_zone0"
  chmod 755 "$mirror/thermal_zone0"
  printf '%%s\n' "$expected" > "$mirror/thermal_zone0/temp"
  printf 'cpu-thermal\n' > "$mirror/thermal_zone0/type"
  chmod 444 "$mirror/thermal_zone0/temp" "$mirror/thermal_zone0/type"
  label_fixture "$mirror" "$thermal_root"
  label_fixture "$mirror/thermal_zone0" "$thermal_root" u:object_r:sysfs_thermal:s0
  label_fixture "$mirror/thermal_zone0/temp" "$thermal_root" u:object_r:sysfs_thermal:s0
  label_fixture "$mirror/thermal_zone0/type" "$thermal_root" u:object_r:sysfs_thermal:s0
  mount --bind "$mirror" "$thermal_root"
fi
[ "$(cat "$target")" = "$expected" ] || { echo "thermal temperature readback failed" >&2; exit 1; }
`, quoteThermalShell(thermalRoot), quoteThermalShell(fixtureRoot), profile.ThermalTemperatureMilliC)
}
