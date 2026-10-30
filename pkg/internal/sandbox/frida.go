package sandbox

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed frida_default.js frida_windows_default.js
var fridaScripts embed.FS

// FridaServerDevicePath is the on-device location every runner pushes
// frida-server to — one source of truth for push/chmod/start/pkill.
const FridaServerDevicePath = "/data/local/tmp/frida-server"

// FridaSession records what instrumentation actually happened, including the
// reasons it did not. A sandbox report that silently omits failed
// instrumentation is worse than no instrumentation, because the absence of
// events reads as "the sample did nothing".
type FridaSession struct {
	Crypto        *CryptoAnalysis `json:"-"` // folded into Report.CryptoAnalysis
	Requested     bool            `json:"requested"`
	Active        bool            `json:"active"`
	Mode          string          `json:"mode,omitempty"`
	DeviceABI     string          `json:"device_abi,omitempty"`
	ServerBinary  string          `json:"server_binary,omitempty"`
	ServerVersion string          `json:"server_version,omitempty"`
	HostVersion   string          `json:"host_version,omitempty"`
	ScriptPath    string          `json:"script_path,omitempty"`
	LogPath       string          `json:"log_path,omitempty"`
	EventCount    int             `json:"event_count"`
	Categories    []string        `json:"categories,omitempty"`
	Warnings      []string        `json:"warnings,omitempty"`
}

func (f *FridaSession) warn(format string, args ...any) {
	f.Warnings = append(f.Warnings, fmt.Sprintf(format, args...))
}

// fridaArchForABI maps an Android ABI to the architecture token used in
// frida-server release filenames.
func fridaArchForABI(abi string) string {
	switch strings.TrimSpace(abi) {
	case "arm64-v8a", "arm64":
		return "arm64"
	case "armeabi-v7a", "armeabi", "arm":
		return "arm"
	case "x86_64":
		return "x86_64"
	case "x86":
		return "x86"
	}
	return ""
}

// fridaWindowsArchForABI maps a Windows architecture or GOARCH token to the
// architecture token used in Windows frida-server release filenames.
func fridaWindowsArchForABI(abi string) string {
	switch strings.ToLower(strings.TrimSpace(abi)) {
	case "amd64", "x86_64", "x64":
		return "x86_64"
	case "386", "x86", "ia32":
		return "x86"
	case "arm64", "aarch64":
		return "arm64"
	}
	return ""
}

// fridaNameMatchesArch reports whether a frida-server filename targets exactly
// arch.
//
// A plain strings.Contains check is wrong here: "frida-server-16.2.1-android-
// x86_64" contains "x86", so an x86 lookup would happily select the 64-bit
// binary and the push would appear to succeed while the server never starts.
// That mismatch is the most common reason Frida "just doesn't work" on a device.
func fridaNameMatchesArch(name, arch string) bool {
	token := "-android-" + arch
	idx := strings.Index(name, token)
	if idx < 0 {
		return false
	}
	rest := name[idx+len(token):]
	if rest == "" {
		return true
	}
	c := rest[0]
	if c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
		return false
	}
	return true
}

// fridaWindowsNameMatchesArch reports whether a Windows frida-server filename
// targets exactly arch (e.g., "frida-server-16.2.1-windows-x86_64.exe" vs
// "frida-server-16.2.1-windows-x86.exe").
func fridaWindowsNameMatchesArch(name, arch string) bool {
	lower := strings.ToLower(name)
	token := "-windows-" + strings.ToLower(arch)
	idx := strings.Index(lower, token)
	if idx < 0 {
		return false
	}
	rest := lower[idx+len(token):]
	if rest == "" || rest == ".exe" {
		return true
	}
	c := rest[0]
	if c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') {
		return false
	}
	return true
}

// fridaSearchDirs returns the directories scanned for a frida-server binary.
// MEGA_FRIDA_SERVER_DIR is honoured first so an operator can pin an exact
// build instead of relying on whatever happens to be in Downloads.
func fridaSearchDirs() []string {
	var dirs []string
	if d := strings.TrimSpace(os.Getenv("MEGA_FRIDA_SERVER_DIR")); d != "" {
		dirs = append(dirs, d)
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			filepath.Join(home, ".mega-analyzer", "frida"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "Desktop"),
			home,
		)
	}
	return dirs
}

// fridaServerForArch finds a frida-server binary matching arch, preferring the
// highest version when several are present.
func fridaServerForArch(arch string) (path string, version string) {
	if arch == "" {
		return "", ""
	}
	bestScore := -1
	for _, dir := range fridaSearchDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasPrefix(name, "frida-server") || !fridaNameMatchesArch(name, arch) {
				continue
			}
			if strings.HasSuffix(name, ".xz") || strings.HasSuffix(name, ".gz") {
				// Still compressed: it cannot be pushed and executed as-is.
				continue
			}
			v := fridaVersionFromName(name)
			if score := fridaVersionScore(v); score > bestScore {
				bestScore = score
				path = filepath.Join(dir, name)
				version = v
			}
		}
	}
	return path, version
}

// fridaWindowsServerForArch finds a Windows frida-server binary matching arch,
// preferring the highest version when several are present. Also returns any
// mismatched architectures discovered in the search directories so callers can
// report an explicit ABI mismatch instead of a generic "not found".
func fridaWindowsServerForArch(arch string) (path string, version string, mismatchedBins []string) {
	targetArch := fridaWindowsArchForABI(arch)
	if targetArch == "" {
		return "", "", nil
	}
	bestScore := -1
	for _, dir := range fridaSearchDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			lower := strings.ToLower(name)
			if !strings.HasPrefix(lower, "frida-server") || !strings.Contains(lower, "-windows-") {
				continue
			}
			if strings.HasSuffix(lower, ".xz") || strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".zip") {
				continue
			}
			if !fridaWindowsNameMatchesArch(name, targetArch) {
				mismatchedBins = append(mismatchedBins, name)
				continue
			}
			v := fridaWindowsVersionFromName(name)
			if score := fridaVersionScore(v); score > bestScore {
				bestScore = score
				path = filepath.Join(dir, name)
				version = v
			}
		}
	}
	return path, version, mismatchedBins
}

// fridaVersionFromName pulls "16.2.1" out of "frida-server-16.2.1-android-arm64".
func fridaVersionFromName(name string) string {
	rest := strings.TrimPrefix(name, "frida-server-")
	if idx := strings.Index(rest, "-android"); idx > 0 {
		return rest[:idx]
	}
	return ""
}

// fridaWindowsVersionFromName pulls "16.2.1" out of "frida-server-16.2.1-windows-x86_64.exe".
func fridaWindowsVersionFromName(name string) string {
	lower := strings.ToLower(name)
	rest := strings.TrimPrefix(lower, "frida-server-")
	if idx := strings.Index(rest, "-windows"); idx > 0 {
		return rest[:idx]
	}
	return ""
}

// fridaVersionScore turns a dotted version into a sortable integer.
func fridaVersionScore(v string) int {
	if v == "" {
		return 0
	}
	score := 0
	for i, part := range strings.SplitN(v, ".", 3) {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			break
		}
		switch i {
		case 0:
			score += n * 1000000
		case 1:
			score += n * 1000
		case 2:
			score += n
		}
	}
	return score
}

// fridaHostVersion returns the version of the host frida CLI, or "".
func fridaHostVersion(fridaBin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, fridaBin, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// fridaMajorMinor reduces a version to "major.minor" for compatibility checks.
func fridaMajorMinor(v string) string {
	parts := strings.SplitN(strings.TrimSpace(v), ".", 3)
	if len(parts) < 2 {
		return strings.TrimSpace(v)
	}
	return parts[0] + "." + parts[1]
}

// fridaServerLive asks the DEVICE whether frida-server is running.
//
// The pre-existing host-side check inspected cmd.ProcessState, which stays nil
// until Wait() is called. Nothing ever called Wait() on the adb shell, so the
// old liveness check reported "running" forever, including long after the
// server had died. Asking the device is the only answer that means anything.
func fridaServerLive(adbPath, serial string) bool {
	out, err := runADB(adbPath, "-s", serial, "shell", "pidof", "frida-server")
	if err == nil && strings.TrimSpace(out) != "" {
		return true
	}
	out, err = runADB(adbPath, "-s", serial, "shell", "ps", "-A")
	return err == nil && strings.Contains(out, "frida-server")
}

// fridaEnsureServer pushes an ABI-matched frida-server and starts it as root.
func fridaEnsureServer(adbPath, serial string, sess *FridaSession, logf func(string, ...any)) bool {
	abi, err := runADB(adbPath, "-s", serial, "shell", "getprop", "ro.product.cpu.abi")
	if err != nil {
		sess.warn("could not read device ABI: %v", err)
		return false
	}
	abi = strings.TrimSpace(abi)
	sess.DeviceABI = abi

	arch := fridaArchForABI(abi)
	if arch == "" {
		sess.warn("unsupported device ABI %q", abi)
		return false
	}

	if fridaServerLive(adbPath, serial) {
		logf("frida: server already running on %s\n", serial)
		return true
	}

	srvPath, srvVersion := fridaServerForArch(arch)
	if srvPath == "" {
		sess.warn("no frida-server binary for %s (%s) found in %s",
			abi, arch, strings.Join(fridaSearchDirs(), ", "))
		return false
	}
	sess.ServerBinary = filepath.Base(srvPath)
	sess.ServerVersion = srvVersion

	// Version parity between the host CLI and the device server is the single
	// most common Frida failure, and its error message is unhelpful, so check it
	// up front and say so plainly.
	if sess.HostVersion != "" && srvVersion != "" &&
		fridaMajorMinor(sess.HostVersion) != fridaMajorMinor(srvVersion) {
		sess.warn("version mismatch: host frida %s vs frida-server %s (install matching versions)",
			sess.HostVersion, srvVersion)
	}

	// Root is required for frida-server. Without it the push succeeds and the
	// exec fails, which used to surface as an empty trace.
	_, _ = runADB(adbPath, "-s", serial, "root")
	time.Sleep(time.Second)

	const remote = FridaServerDevicePath
	_, _ = runADB(adbPath, "-s", serial, "shell", "pkill", "-f", FridaServerDevicePath)
	if _, err := runADB(adbPath, "-s", serial, "push", srvPath, remote); err != nil {
		sess.warn("push frida-server: %v", err)
		return false
	}
	if _, err := runADB(adbPath, "-s", serial, "shell", "chmod", "755", remote); err != nil {
		sess.warn("chmod frida-server: %v", err)
		return false
	}

	start := exec.Command(adbPath, "-s", serial, "shell", remote, "-D")
	start.Stdout = nil
	start.Stderr = nil
	if err := start.Start(); err != nil {
		sess.warn("start frida-server: %v", err)
		return false
	}

	// Verify on the device instead of assuming the spawn worked.
	for i := 0; i < 12; i++ {
		time.Sleep(500 * time.Millisecond)
		if fridaServerLive(adbPath, serial) {
			logf("frida: server %s running on %s (%s)\n", srvVersion, serial, abi)
			return true
		}
	}
	sess.warn("frida-server did not come up on the device (needs root; check SELinux and that %s matches %s)",
		sess.ServerBinary, abi)
	return false
}

// fridaWriteScript materialises the instrumentation script for this session and
// returns its path. A caller-supplied script always wins.
func fridaWriteScript(sessionDir, userScript string) (string, error) {
	if userScript != "" {
		abs, err := filepath.Abs(userScript)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("frida script %s: %w", userScript, err)
		}
		return abs, nil
	}
	data, err := fridaScripts.ReadFile("frida_default.js")
	if err != nil {
		return "", err
	}
	dest := filepath.Join(sessionDir, "frida_default.js")
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

// fridaWriteWindowsScript materialises the Windows WinAPI instrumentation script
// into sessionDir with the requested categories embedded, or validates and
// returns userScript when supplied.
func fridaWriteWindowsScript(sessionDir, userScript string, categories []string) (string, error) {
	if userScript != "" {
		abs, err := filepath.Abs(userScript)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("frida windows script %s: %w", userScript, err)
		}
		return abs, nil
	}
	data, err := fridaScripts.ReadFile("frida_windows_default.js")
	if err != nil {
		return "", err
	}
	cats := categories
	if len(cats) == 0 {
		cats = SupportedAPICategories()
	}
	catsJSON, err := json.Marshal(cats)
	if err != nil {
		return "", err
	}
	header := fmt.Sprintf("var __MEGA_ENABLED_CATEGORIES = %s;\n", string(catsJSON))
	dest := filepath.Join(sessionDir, "frida_windows_default.js")
	if err := os.WriteFile(dest, append([]byte(header), data...), 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

// fridaRun starts an instrumentation session against packageName and streams its
// output to a log file inside the session directory. It returns a stop function.
//
// Two modes, and the distinction matters:
//
//   - spawn: the app is force-stopped and relaunched under Frida, so hooks are
//     installed before any application code runs. Anything a sample does in
//     Application.onCreate or a static initialiser (which is where packers and
//     droppers do their work) is only visible this way.
//   - attach: hooks are installed into the already-running process. Cheaper and
//     non-disruptive, but structurally blind to app startup.
func fridaRun(ctx context.Context, cfg Config, sessionDir, packageName string, sess *FridaSession, logf func(string, ...any)) func() {
	fridaBin, err := exec.LookPath("frida")
	if err != nil {
		sess.warn("frida CLI not found on PATH (pip install frida-tools)")
		return nil
	}
	sess.HostVersion = fridaHostVersion(fridaBin)

	scriptPath, err := fridaWriteScript(sessionDir, cfg.FridaScript)
	if err != nil {
		sess.warn("prepare frida script: %v", err)
		return nil
	}
	sess.ScriptPath = scriptPath

	logPath := filepath.Join(sessionDir, "frida.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		sess.warn("create frida log: %v", err)
		return nil
	}
	sess.LogPath = logPath

	args := []string{"-U", "-l", scriptPath, "-q"}
	if cfg.AndroidDevice != "" {
		args = append([]string{"-D", cfg.AndroidDevice}, args[1:]...)
	}
	if cfg.FridaSpawn {
		sess.Mode = "spawn"
		args = append(args, "-f", packageName)
	} else {
		sess.Mode = "attach"
		args = append(args, "-n", packageName)
	}

	cmd := exec.CommandContext(ctx, fridaBin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// frida exits immediately on EOF unless it has a stdin to hold.
	stdin, _ := cmd.StdinPipe()

	if err := cmd.Start(); err != nil {
		sess.warn("start frida: %v", err)
		_ = logFile.Close()
		return nil
	}
	sess.Active = true
	logf("frida: %s mode on %s, script %s\n", sess.Mode, packageName, filepath.Base(scriptPath))

	stopped := false
	return func() {
		if stopped {
			return
		}
		stopped = true
		if stdin != nil {
			_ = stdin.Close()
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		_ = logFile.Close()
		fridaSummarise(logPath, sess)
	}
}

// fridaSummarise counts emitted events by category so the report carries a
// verdict-shaped summary instead of only a log file path.
func fridaSummarise(logPath string, sess *FridaSession) {
	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()
	sess.Crypto = &CryptoAnalysis{Status: "no_material", Materials: []CryptoMaterial{}}
	seen := map[string]bool{}
	var order []string
	count := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "FRIDA_EVT ")
		if idx < 0 {
			continue
		}
		payload := line[idx+len("FRIDA_EVT "):]
		var event struct {
			Category  string `json:"cat"`
			Action    string `json:"act"`
			Timestamp int64  `json:"t"`
			PID       int    `json:"pid"`
			Algorithm string `json:"algorithm"`
			Operation string `json:"operation"`
			KeyHex    string `json:"key_hex"`
			IVHex     string `json:"iv_hex"`
		}
		if json.Unmarshal([]byte(payload), &event) != nil || event.Category == "" {
			continue
		}
		count++
		if event.Category == "crypto_key" && (event.Action == "SecretKeySpec" || event.Action == "Cipher.init") {
			sess.Crypto.add(CryptoMaterial{Source: "frida-android", Function: event.Action,
				PID: event.PID, ObservedAt: time.UnixMilli(event.Timestamp).UTC(),
				Algorithm: event.Algorithm, Operation: event.Operation, KeyHex: event.KeyHex, IVHex: event.IVHex})
		}
		cat := event.Category
		if !seen[cat] {
			seen[cat] = true
			order = append(order, cat)
		}
	}
	sess.EventCount = count
	sess.Categories = order
	if err := scanner.Err(); err != nil {
		sess.Crypto.Truncated = true
		sess.warn("read Frida events: %v", err)
	}
}
