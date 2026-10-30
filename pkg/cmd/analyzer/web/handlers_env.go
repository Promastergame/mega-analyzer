// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/androidsdk"
	"mega-analyzer/pkg/internal/sandbox"
)

// handlePkgVersion serves /api/pkg-version.
// /api/pkg-version?pkg=com.example — checks if a package is already installed
// on the connected Android device and returns its installed version name.
func (s *Server) handlePkgVersion(w http.ResponseWriter, r *http.Request) {
	pkg := r.URL.Query().Get("pkg")
	w.Header().Set("Content-Type", "application/json")
	if pkg == "" || !validAndroidPackage(pkg) {
		w.Write([]byte(`{"installed":false}`))
		return
	}
	serial := RequestDeviceSerial(r)
	if serial == "" {
		w.Write([]byte(`{"installed":false}`))
		return
	}
	adb := liveADB()
	// Hard timeouts: this is an HTTP handler and a wedged adbd must not
	// hang the request (and the web UI) forever.
	pkgCtx, pkgCancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer pkgCancel()
	out, err := exec.CommandContext(pkgCtx, adb, "-s", serial, "shell", "pm", "list", "packages", pkg).Output()
	if err != nil || !strings.Contains(string(out), pkg) {
		w.Write([]byte(`{"installed":false}`))
		return
	}
	// Get the version name
	ver := ""
	verCtx, verCancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer verCancel()
	vout, verr := exec.CommandContext(verCtx, adb, "-s", serial, "shell",
		"dumpsys", "package", pkg).Output()
	if verr == nil {
		for _, ln := range strings.Split(string(vout), "\n") {
			if strings.Contains(ln, "versionName=") {
				parts := strings.SplitN(strings.TrimSpace(ln), "=", 2)
				if len(parts) == 2 {
					ver = strings.TrimSpace(parts[1])
				}
				break
			}
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"installed": true, "version": ver})
}

// handleEnv serves /api/env.
// Available analysis environments (which guest OSes / devices can run here):
// the native host, detected VirtualBox / VMware guests, and Android AVDs/devices.
func hostPayload() map[string]any {
	host := hostPlatform().payload()
	host["sandbox"] = sandbox.NativeSandboxReadiness()
	return host
}

// This endpoint must not wait for adb, Java or a hypervisor to answer.
func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hostPayload())
}

func (s *Server) handleEnv(w http.ResponseWriter, r *http.Request) {
	tc := androidsdk.Detect()
	avds := listAVDs(tc.Emulator, tc.AVDManager)
	if avds == nil {
		avds = []string{}
	}
	deviceList, deviceErr := detectedAndroidDevices()
	devices := []string{}
	for _, d := range deviceList {
		if d.State != "device" {
			continue
		}
		label := d.Serial
		if d.Model != "" {
			label = d.Model + " (" + d.Serial + ")"
		}
		devices = append(devices, label)
	}

	vbox := detectVBoxVMs()
	if vbox == nil {
		vbox = []vmEntry{}
	}
	vmware := detectVMwareVMs()
	if vmware == nil {
		vmware = []vmEntry{}
	}

	warnings := []string{}
	// A missing optional adb installation is normal, not an error or a device.
	_, adbErr := exec.LookPath(liveADB())
	adbAvailable := adbErr == nil
	if deviceErr != nil && adbAvailable {
		warnings = append(warnings, "Android discovery: "+deviceErr.Error())
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"windows": runtime.GOOS == "windows", "host": hostPayload(), "vbox": vbox, "vmware": vmware,
		"vmwareExecution": runtime.GOOS == "windows" && vmwareToolPath() != "",
		"warnings":        warnings,
		"android": map[string]any{
			"detected": tc.Detected, "sdkInstalled": tc.Detected, "adbAvailable": adbAvailable,
			"emulatorAvailable": tc.Emulator != "", "avds": avds, "devices": devices, "deviceDetails": deviceList,
			"networkIsolationSupported": false,
		},
	})
}

// handleMeta serves /api/meta.
// Real bundle counts (SAST rules, trackers) for the UI badges.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	sast, trk := uiBadgeCounts()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"sastRules": sast, "trackers": trk})
}
