package web

import (
	"fmt"
	"mega-analyzer/pkg/internal/androidsdk"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Validate the whole flag/value pair instead of silently deleting spaces,
// backslashes or ':' from values (which used to break args, Frida paths and adb TCP serials).
func validateSandboxRequest(target, consent, filename, hostOS string, args []string) ([]string, error) {
	if consent != "yes" {
		return nil, fmt.Errorf("confirm use of a disposable analysis host/device before real execution")
	}
	kind, id, ok := strings.Cut(target, ":")
	if !ok {
		return nil, fmt.Errorf("select an explicit analysis target")
	}
	android := kind == "device" || kind == "avd"
	switch kind {
	case "host":
		return nil, fmt.Errorf("native execution on the analyzer host is blocked; use the remote VM collector with -sandbox-remote-config")
	case "device":
		if !androidsdk.ValidDeviceSerial(id) {
			return nil, fmt.Errorf("invalid adb serial")
		}
	case "avd":
		if !androidsdk.ValidAVDName(id) {
			return nil, fmt.Errorf("invalid AVD name")
		}
	case "vmware":
		if hostOS != "windows" || id == "" || len(target) > 128 || strings.ContainsAny(id, "\\/\x00\r\n ") {
			return nil, fmt.Errorf("select a detected VMware Windows guest on a Windows analyzer host")
		}
	default:
		return nil, fmt.Errorf("VM execution is not implemented; choose a supported target")
	}
	ext := strings.ToLower(filepath.Ext(filename))
	supported := false
	if android {
		supported = ext == ".apk" || ext == ".xapk" || ext == ".apks"
	} else {
		supported = ext == ".exe" || ext == ".com" || ext == ".bat" || ext == ".cmd" || ext == ".ps1"
	}
	if !supported {
		return nil, fmt.Errorf("selected target cannot execute %s; use static analysis for this format", ext)
	}
	values := map[string]bool{"-sandbox-duration": true, "-sandbox-memory": true, "-sandbox-cpu-cores": true, "-sandbox-args": true, "-sandbox-profile": true, "-sandbox-desktop": true, "-sandbox-device": true, "-sandbox-avd": true, "-sandbox-resolution": true, "-sandbox-orientation": true, "-sandbox-locale": true, "-sandbox-timezone": true, "-sandbox-frida-script": true}
	switches := map[string]bool{"-sandbox-allow-net": true, "-android-sandbox": true, "-sandbox-uninstall-after": true, "-sandbox-capture-traffic": true, "-sandbox-frida": true}
	result := []string{}
	seen := map[string]bool{}
	network := false
	for i := 0; i < len(args); i++ {
		key := args[i]
		if seen[key] {
			return nil, fmt.Errorf("duplicate dynamic-analysis option %s", key)
		}
		seen[key] = true
		if switches[key] {
			if key == "-sandbox-allow-net" {
				if kind == "vmware" {
					return nil, fmt.Errorf("VMware analysis currently requires disconnected virtual network adapters")
				}
				network = true
			} else if !android {
				return nil, fmt.Errorf("%s requires Android", key)
			}
			if key != "-android-sandbox" {
				result = append(result, key)
			}
			continue
		}
		if !values[key] || i+1 >= len(args) {
			return nil, fmt.Errorf("unsupported or incomplete dynamic-analysis option %s", key)
		}
		i++
		value := args[i]
		if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("invalid value for %s", key)
		}
		switch key {
		case "-sandbox-duration", "-sandbox-memory", "-sandbox-cpu-cores":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%s must be a number", key)
			}
			// The only duration ceiling is representational overflow, not a product limit.
			min, max := int64(0), (int64(1<<63-1) / int64(time.Second))
			if key == "-sandbox-memory" {
				min, max = 128, 131072
			}
			if key == "-sandbox-cpu-cores" {
				min, max = 1, 1024
			}
			if n < min || n > max || (key == "-sandbox-duration" && n > 0 && n < 5) {
				return nil, fmt.Errorf("%s is out of range", key)
			}
			if kind == "device" && key != "-sandbox-duration" {
				return nil, fmt.Errorf("CPU/RAM limits cannot be applied to an attached Android device")
			}
		case "-sandbox-args":
			if android {
				return nil, fmt.Errorf("launch arguments require native Windows execution")
			}
		case "-sandbox-desktop":
			if kind != "vmware" || (value != "background" && value != "interactive") {
				return nil, fmt.Errorf("desktop mode requires VMware and background or interactive")
			}
		case "-sandbox-profile":
			if android || value != "basic" {
				return nil, fmt.Errorf("only the real basic monitoring profile is available")
			}
		case "-sandbox-device":
			if kind != "device" || value != id {
				return nil, fmt.Errorf("device selection conflicts with flags")
			}
			continue
		case "-sandbox-avd":
			if kind != "avd" || value != id {
				return nil, fmt.Errorf("AVD selection conflicts with flags")
			}
			continue
		default:
			if !android {
				return nil, fmt.Errorf("%s requires Android", key)
			}
		}
		result = append(result, key, value)
	}
	if android && !network {
		return nil, fmt.Errorf("Android network isolation is unavailable; execution remains blocked, and no network settings were changed")
	}
	if android {
		result = append(result, "-android-sandbox")
		if kind == "device" {
			result = append(result, "-sandbox-device", id)
		} else {
			result = append(result, "-sandbox-avd", id)
		}
	}
	return result, nil
}
