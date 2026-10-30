// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// vmEntry describes one detected guest virtual machine.
type vmEntry struct {
	Name       string `json:"name"`
	OSType     string `json:"osType,omitempty"`
	Running    bool   `json:"running"`
	Registered bool   `json:"registered"`
	ID         string `json:"id,omitempty"`
	ConfigPath string `json:"configPath,omitempty"`
	Source     string `json:"source,omitempty"`
}

var vboxVMLine = regexp.MustCompile(`^"(.+)"\s+\{[0-9a-fA-F-]+\}`)

// findTool resolves a CLI tool by PATH first, then a few well-known install
// locations, so detection works even when the tool is not on PATH.
func findTool(name string, fallbacks ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, fb := range fallbacks {
		if fb == "" {
			continue
		}
		fb = os.ExpandEnv(fb)
		if info, err := os.Stat(fb); err == nil && info.Mode().IsRegular() {
			return fb
		}
	}
	return ""
}

// detectVBoxVMs lists VirtualBox guests via VBoxManage. Returns nil when
// VBoxManage is not installed. Best-effort and time-bounded.
func detectVBoxVMs() []vmEntry {
	mgr := findTool("VBoxManage",
		`${ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe`,
		`${ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe`,
		"/usr/bin/VBoxManage", "/usr/local/bin/VBoxManage")
	if mgr == "" {
		return nil
	}

	running := map[string]bool{}
	if out, err := runToolBounded(mgr, "list", "runningvms"); err == nil {
		for _, ln := range strings.Split(out, "\n") {
			if m := vboxVMLine.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				running[m[1]] = true
			}
		}
	}

	out, err := runToolBounded(mgr, "list", "vms")
	if err != nil {
		return nil
	}
	var vms []vmEntry
	for _, ln := range strings.Split(out, "\n") {
		m := vboxVMLine.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		name := m[1]
		e := vmEntry{Name: name, Running: running[name]}
		if info, err := runToolBounded(mgr, "showvminfo", name, "--machinereadable"); err == nil {
			for _, il := range strings.Split(info, "\n") {
				if strings.HasPrefix(il, "ostype=") {
					e.OSType = strings.Trim(strings.TrimPrefix(strings.TrimSpace(il), "ostype="), `"`)
					break
				}
			}
		}
		vms = append(vms, e)
	}
	return vms
}
