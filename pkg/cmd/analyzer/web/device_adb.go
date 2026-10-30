// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/androidsdk"
)

// LiveSerial, LiveADB, LiveDeviceSize and FindScrcpyServer are the exported
// surface used by package main's live handlers. There is exactly one
// implementation (here); main must not fork its own copies.
func LiveSerial() string { return liveSerial() }

// LiveADB resolves the adb executable, see liveADB.
func LiveADB() string { return liveADB() }

// LiveDeviceSize returns the device screen resolution, see liveDeviceSize.
func LiveDeviceSize(adb, serial string) (int, int) { return liveDeviceSize(adb, serial) }

// FindScrcpyServer looks for the scrcpy-server file, see findScrcpyServer.
func FindScrcpyServer() string { return findScrcpyServer() }

// liveADB resolves the adb executable from PATH, the SDK, or the scrcpy bundle.
// scrcpy ships its own adb.exe, so if the user has scrcpy but not a full SDK
// installation we can still talk to the device.
func liveADB() string {
	if p, err := exec.LookPath("adb"); err == nil {
		return p
	}
	if tc := androidsdk.Detect(); tc.Detected && tc.ADB != "" {
		return tc.ADB
	}
	// scrcpy bundles adb.exe next to scrcpy-server — check that directory.
	if sp := findScrcpyServer(); sp != "" {
		for _, name := range []string{"adb.exe", "adb"} {
			cand := filepath.Join(filepath.Dir(sp), name)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	return "adb"
}

// liveSerial returns the first device adb currently reports as "device".
func liveSerial() string {
	devices, _ := detectedAndroidDevices()
	serial, _ := androidsdk.SelectDevice(devices, "")
	return serial
}

func detectedAndroidDevices() ([]androidsdk.Device, error) {
	out, err := runToolBounded(liveADB(), "devices", "-l")
	if err != nil {
		return []androidsdk.Device{}, err
	}
	return androidsdk.ParseADBDevices(out), nil
}

type deviceSize struct{ w, h int }

var (
	deviceSizeCache   = map[string]deviceSize{}
	deviceSizeCacheMu sync.Mutex
)

// liveDeviceSize returns the device screen resolution (defaults to 1080x1920).
// Result is cached per serial so repeated tap calls don't run adb shell wm size each time.
func liveDeviceSize(adb, serial string) (int, int) {
	deviceSizeCacheMu.Lock()
	if s, ok := deviceSizeCache[serial]; ok {
		deviceSizeCacheMu.Unlock()
		return s.w, s.h
	}
	deviceSizeCacheMu.Unlock()

	out, err := exec.Command(adb, "-s", serial, "shell", "wm", "size").Output()
	if err == nil {
		// "Physical size: 1080x2400"
		if i := strings.LastIndex(string(out), ":"); i >= 0 {
			parts := strings.Split(strings.TrimSpace(string(out)[i+1:]), "x")
			if len(parts) == 2 {
				w, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
				h, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
				if e1 == nil && e2 == nil && w > 0 && h > 0 {
					deviceSizeCacheMu.Lock()
					deviceSizeCache[serial] = deviceSize{w, h}
					deviceSizeCacheMu.Unlock()
					return w, h
				}
			}
		}
	}
	return 1080, 1920
}

// liveSafeKey whitelists the navigation keys the UI is allowed to send.
func liveSafeKey(k string) bool {
	switch k {
	case "KEYCODE_HOME", "KEYCODE_BACK", "KEYCODE_APP_SWITCH",
		"KEYCODE_VOLUME_UP", "KEYCODE_VOLUME_DOWN", "KEYCODE_POWER", "KEYCODE_MENU":
		return true
	}
	return false
}

// listAVDs returns the Android virtual devices available on this machine.
// It tries three discovery methods in order: emulator -list-avds,
// avdmanager list avd -c, and a direct filesystem scan of ~/.android/avd/.
// All are best-effort so a missing tool or empty dir returns an empty slice.
func listAVDs(emulator, avdmanager string) []string {
	// Method 1: emulator -list-avds
	if emulator != "" {
		if out, err := runToolBounded(emulator, "-list-avds"); err == nil {
			names := androidsdk.ParseAVDNames(out)
			if len(names) > 0 {
				return names
			}
		}
	}

	// Method 2: avdmanager list avd -c (compact: one name per line)
	if avdmanager != "" {
		if out, err := runToolBounded(avdmanager, "list", "avd", "-c"); err == nil {
			names := androidsdk.ParseAVDNames(out)
			if len(names) > 0 {
				return names
			}
		}
	}

	// Method 3: filesystem scan — ~/.android/avd/<name>.ini lists every AVD
	// regardless of whether the SDK tools are on PATH.
	if home, err := os.UserHomeDir(); err == nil {
		avdDir := filepath.Join(home, ".android", "avd")
		entries, err := os.ReadDir(avdDir)
		if err == nil {
			var names []string
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".ini") && androidsdk.ValidAVDName(strings.TrimSuffix(e.Name(), ".ini")) {
					name := strings.TrimSuffix(e.Name(), ".ini")
					if androidsdk.ValidAVDName(name) {
						if fi, err := os.Stat(filepath.Join(avdDir, name+".avd", "config.ini")); err == nil && !fi.IsDir() {
							names = append(names, name)
						}
					}
				}
			}
			if len(names) > 0 {
				return names
			}
		}
	}

	return nil
}

// findScrcpyServer looks for the scrcpy-server file next to scrcpy.exe, or in
// common installation directories.
func findScrcpyServer() string {
	// Check next to scrcpy.exe
	scrcpy := findTool("scrcpy",
		`${USERPROFILE}\Desktop\scrcpy-win64-v4.0\scrcpy.exe`,
		`${USERPROFILE}\scrcpy\scrcpy.exe`,
		`C:\scrcpy\scrcpy.exe`,
		`/usr/bin/scrcpy`, `/usr/local/bin/scrcpy`,
	)
	if scrcpy != "" {
		candidate := filepath.Join(filepath.Dir(scrcpy), "scrcpy-server")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Also scan Desktop and Downloads for scrcpy-* directories
	if home, err := os.UserHomeDir(); err == nil {
		for _, base := range []string{"Desktop", "Downloads"} {
			entries, _ := os.ReadDir(filepath.Join(home, base))
			for _, e := range entries {
				if !e.IsDir() || !strings.HasPrefix(e.Name(), "scrcpy") {
					continue
				}
				p := filepath.Join(home, base, e.Name(), "scrcpy-server")
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	return ""
}
