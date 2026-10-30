package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// detectVMwareVMs discovers VM definitions, not installed software or vmrun
// status messages. Every candidate must resolve to a real, readable VMX file.
func detectVMwareVMs() []vmEntry {
	var running string
	if tool := findTool("vmrun", `${ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe`, `${ProgramFiles}\VMware\VMware Workstation\vmrun.exe`, "/usr/bin/vmrun", "/Applications/VMware Fusion.app/Contents/Library/vmrun"); tool != "" {
		if out, err := runToolBounded(tool, "list"); err == nil {
			running = out
		}
	}
	var inventories, dirs []string
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		inventories = append(inventories, filepath.Join(appdata, "VMware", "inventory.vmls"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		inventories = append(inventories, filepath.Join(home, ".vmware", "inventory.vmls"), filepath.Join(home, "Library", "Application Support", "VMware Fusion", "inventory.vmls"))
		dirs = append(dirs, filepath.Join(home, "Documents", "Virtual Machines"), filepath.Join(home, "Virtual Machines"))
	}
	if pub := os.Getenv("PUBLIC"); pub != "" {
		dirs = append(dirs, filepath.Join(pub, "Documents", "Virtual Machines"))
	}
	return collectVMwareVMs(running, inventories, dirs)
}

func collectVMwareVMs(running string, inventories, dirs []string) []vmEntry {
	result := make([]vmEntry, 0)
	seen := make(map[string]int)
	add := func(candidate, source string, active bool) {
		path, props, ok := readVMXDefinition(candidate)
		if !ok {
			return
		}
		registered := active || source == "inventory"
		key := path
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if i, ok := seen[key]; ok {
			result[i].Running = result[i].Running || active
			result[i].Registered = result[i].Registered || registered
			return
		}
		name := strings.TrimSpace(props["displayname"])
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		}
		sum := sha256.Sum256([]byte(key))
		seen[key] = len(result)
		result = append(result, vmEntry{Name: name, OSType: props["guestos"], Running: active, Registered: registered, ID: "vmware:" + hex.EncodeToString(sum[:12]), ConfigPath: path, Source: source})
	}
	// Locale-independent: never interpret a heading, count, warning, or an error
	// as a guest. Even a line ending in .vmx must be an existing absolute path.
	for _, line := range strings.Split(running, "\n") {
		add(line, "running", true)
	}
	for _, inventory := range inventories {
		data, err := readSmallVMFile(inventory)
		if err != nil {
			continue
		}
	// VMware writes library entries as vmlistN.config (older tooling used
	// indexN.filename); accept both so a registered VM is not misreported
	// as a stray config file found on disk.
	for key, value := range parseVMProperties(string(data)) {
		if strings.HasSuffix(key, ".filename") || strings.HasSuffix(key, ".config") {
			add(value, "inventory", false)
		}
	}
	}
	// Deliberately bounded to conventional directories and one directory level.
	// No full-disk search and no interpretation of directories as VMX files.
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			if !entry.IsDir() {
				add(path, "discovered", false)
				continue
			}
			children, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, child := range children {
				if !child.IsDir() {
					add(filepath.Join(path, child.Name()), "discovered", false)
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Running != result[j].Running {
			return result[i].Running
		}
		a, b := strings.ToLower(result[i].Name), strings.ToLower(result[j].Name)
		if a != b {
			return a < b
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func readSmallVMFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return nil, os.ErrInvalid
	}
	return io.ReadAll(io.LimitReader(f, 2<<20))
}

func readVMXDefinition(candidate string) (string, map[string]string, bool) {
	path := strings.Trim(strings.TrimSpace(strings.TrimPrefix(candidate, "\ufeff")), "\"")
	if strings.ContainsAny(path, "\r\n\x00") || !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".vmx") {
		return "", nil, false
	}
	path, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", nil, false
	}
	data, err := readSmallVMFile(path)
	if err != nil {
		return "", nil, false
	}
	props := parseVMProperties(string(data))
	version, err := strconv.Atoi(props["config.version"])
	if err != nil || version <= 0 || (props["virtualhw.version"] == "" && props["guestos"] == "") {
		return "", nil, false
	}
	return path, props, true
}

func parseVMProperties(text string) map[string]string {
	props := make(map[string]string)
	for _, line := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			continue
		}
		key, value := strings.ToLower(strings.TrimSpace(pair[0])), strings.TrimSpace(pair[1])
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
			value = strings.ReplaceAll(value, `\"`, `"`)
			value = strings.ReplaceAll(value, `\\`, `\`)
		}
		props[key] = value
	}
	return props
}
