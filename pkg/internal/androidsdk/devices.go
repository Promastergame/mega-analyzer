package androidsdk

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Device is an actual adb row, not an SDK installation or a placeholder.
type Device struct {
	Serial string `json:"serial"`
	Model  string `json:"model,omitempty"`
	State  string `json:"state"`
}

var serialRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\[\]%-]*$`)
var avdRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func ValidDeviceSerial(s string) bool {
	return len(s) <= 256 && !strings.HasSuffix(s, ":") && serialRE.MatchString(s)
}
func ValidAVDName(s string) bool { return len(s) <= 200 && avdRE.MatchString(s) }

func ParseADBDevices(out string) []Device {
	devices := []Device{}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "\ufeff")))
		if len(fields) < 2 || !ValidDeviceSerial(fields[0]) || seen[fields[0]] {
			continue
		}
		state := fields[1]
		switch state {
		case "device", "offline", "unauthorized", "recovery", "sideload", "bootloader":
		case "no":
			if len(fields) < 3 || fields[2] != "permissions" {
				continue
			}
			state = "no permissions"
		default:
			continue
		}
		d := Device{Serial: fields[0], State: state}
		for _, field := range fields[2:] {
			if strings.HasPrefix(field, "model:") {
				d.Model = strings.ReplaceAll(strings.TrimPrefix(field, "model:"), "_", " ")
			}
		}
		seen[d.Serial] = true
		devices = append(devices, d)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Serial < devices[j].Serial })
	return devices
}

// SelectDevice never silently substitutes a different handset.
func SelectDevice(devices []Device, serial string) (string, error) {
	if serial != "" && !ValidDeviceSerial(serial) {
		return "", fmt.Errorf("invalid Android device serial")
	}
	ready := []string{}
	for _, d := range devices {
		if serial != "" && d.Serial == serial {
			if d.State != "device" {
				return "", fmt.Errorf("Android device %s is %s; authorize USB debugging or reconnect this device", serial, d.State)
			}
			return serial, nil
		}
		if d.State == "device" {
			ready = append(ready, d.Serial)
		}
	}
	if serial != "" {
		return "", fmt.Errorf("selected Android device %s is not connected; no other device was selected", serial)
	}
	if len(ready) == 1 {
		return ready[0], nil
	}
	if len(ready) > 1 {
		return "", fmt.Errorf("multiple Android devices are connected; select one explicitly with -sandbox-device")
	}
	if len(devices) > 0 {
		return "", fmt.Errorf("no ready Android device; check USB debugging authorization and offline devices")
	}
	return "", fmt.Errorf("no active Android devices or emulators found")
}

func ParseAVDNames(out string) []string {
	names := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if !ValidAVDName(name) || seen[name] {
			continue
		}
		switch strings.ToUpper(name) {
		case "INFO", "WARNING", "ERROR", "PANIC", "OK":
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
