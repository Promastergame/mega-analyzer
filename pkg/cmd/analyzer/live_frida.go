package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/cmd/analyzer/web"
	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/wsx"
)

// fridaState tracks the pushed/running frida-server on the device.
var fridaState struct {
	mu     sync.Mutex
	serial string
	srvCmd *exec.Cmd
}

// findFridaCLI returns the path to the frida CLI executable, or "".
func findFridaCLI() string {
	if p, err := exec.LookPath("frida"); err == nil {
		return p
	}
	return ""
}

// findFridaPs returns the path to frida-ps, or "".
func findFridaPs() string {
	if p, err := exec.LookPath("frida-ps"); err == nil {
		return p
	}
	// frida-ps is usually next to frida
	if frida := findFridaCLI(); frida != "" {
		candidate := filepath.Join(filepath.Dir(frida), "frida-ps")
		if runtime.GOOS == "windows" {
			candidate += ".exe"
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// findFridaServer looks for a frida-server binary in common locations.
// frida-server must match the device ABI (arm64, arm, x86, x86_64).
func findFridaServer() string {
	home, _ := os.UserHomeDir()
	// Scan Desktop / Downloads for frida-server-* files.
	for _, base := range []string{
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Downloads"),
		home,
	} {
		entries, _ := os.ReadDir(base)
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasPrefix(n, "frida-server") {
				continue
			}
			p := filepath.Join(base, n)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// runADB runs a one-shot adb command with a hard timeout so a wedged
// device or adbd can't hang the live runner forever.
func runADB(adb, serial string, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, adb, append([]string{"-s", serial}, args...)...).CombinedOutput()
}

// runTool runs a one-shot host build/sign tool (apktool, keytool, apksigner)
// with a hard timeout; a stuck JVM would otherwise block repacking forever.
func runTool(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// pushAndStartFridaServer pushes frida-server to the device and starts it.
// Returns an error if frida-server binary is not found or push fails.
// Idempotent: if already running on the same serial, returns nil.
func pushAndStartFridaServer(adb, serial string) error {
	fridaState.mu.Lock()
	defer fridaState.mu.Unlock()

	if fridaState.serial == serial && fridaState.srvCmd != nil {
		if fridaState.srvCmd.ProcessState == nil { // still running
			return nil
		}
	}

	srvPath := findFridaServer()
	if srvPath == "" {
		return fmt.Errorf("frida-server binary not found (put frida-server-*-android-* on Desktop or Downloads)")
	}

	// Try `adb root` so frida-server has full access. Best-effort: it
	// legitimately fails on non-rooted devices and the push below reports
	// the real error if root was required.
	_, _ = runADB(adb, serial, 15*time.Second, "root")
	time.Sleep(500 * time.Millisecond)

	// Push binary.
	if out, err := runADB(adb, serial, 2*time.Minute, "push", srvPath, sandbox.FridaServerDevicePath); err != nil {
		return fmt.Errorf("push frida-server: %w — %s", err, out)
	}
	// Make executable.
	if out, err := runADB(adb, serial, 15*time.Second, "shell", "chmod", "+x", sandbox.FridaServerDevicePath); err != nil {
		return fmt.Errorf("chmod: %w — %s", err, out)
	}
	// Kill any leftover instance.
	_, _ = runADB(adb, serial, 15*time.Second, "shell", "pkill", "-f", "frida-server")
	time.Sleep(200 * time.Millisecond)

	// Start frida-server in background via adb.
	cmd := exec.Command(adb, "-s", serial, "shell", sandbox.FridaServerDevicePath, "-D")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start frida-server: %w", err)
	}
	time.Sleep(800 * time.Millisecond) // let it bind

	fridaState.serial = serial
	fridaState.srvCmd = cmd
	return nil
}

// handleFridaStatus reports frida tool availability and server status.
func handleFridaStatus(w http.ResponseWriter, r *http.Request) {
	type status struct {
		FridaCLI    bool   `json:"frida_cli"`
		FridaPs     bool   `json:"frida_ps"`
		ServerBin   bool   `json:"server_bin"`
		ServerReady bool   `json:"server_ready"`
		FridaPath   string `json:"frida_path,omitempty"`
		Note        string `json:"note,omitempty"`
	}
	s := status{
		FridaCLI:  findFridaCLI() != "",
		FridaPs:   findFridaPs() != "",
		ServerBin: findFridaServer() != "",
	}
	s.FridaPath = findFridaCLI()
	fridaState.mu.Lock()
	s.ServerReady = fridaState.srvCmd != nil && fridaState.srvCmd.ProcessState == nil
	fridaState.mu.Unlock()
	if !s.FridaCLI {
		s.Note = "Install frida-tools: pip install frida-tools"
	} else if !s.ServerBin {
		s.Note = "Download frida-server-*-android-* from github.com/frida/frida/releases and place on Desktop/Downloads"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

// fridaTargetHost reports whether the request targets the analyzer host
// itself (?host=1) instead of the USB Android device. On the host, frida
// works locally without frida-server: `frida-ps` lists PC processes and
// `frida -p <pid>` attaches to them.
func fridaTargetHost(r *http.Request) bool {
	return r.URL.Query().Get("host") == "1"
}

// fridaReplArgs builds the frida CLI arguments for a REPL session:
// local attach on the host, USB attach on Android.
func fridaReplArgs(host bool, pid string) []string {
	if host {
		return []string{"-p", pid}
	}
	return []string{"-U", "-p", pid}
}

type fridaProc struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

// parseFridaPsTable parses `frida-ps` output (same columns with or without -U).
func parseFridaPsTable(out string) []fridaProc {
	var procs []fridaProc
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") || strings.HasPrefix(line, "---") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		procs = append(procs, fridaProc{PID: pid, Name: strings.Join(fields[1:], " ")})
	}
	return procs
}

// handleFridaProcesses lists USB processes via frida-ps.
func handleFridaProcesses(w http.ResponseWriter, r *http.Request) {
	host := fridaTargetHost(r)
	if !host {
		serial := web.LiveSerial()
		if serial == "" {
			http.Error(w, "no device", http.StatusNotFound)
			return
		}
	}
	fridaPs := findFridaPs()
	if fridaPs == "" {
		http.Error(w, "frida-ps not found — pip install frida-tools", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	var out []byte
	var err error
	if host {
		out, err = exec.CommandContext(ctx, fridaPs).CombinedOutput()
	} else {
		out, err = exec.CommandContext(ctx, fridaPs, "-U").CombinedOutput()
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("frida-ps: %v — %s", err, out), http.StatusInternalServerError)
		return
	}

	procs := parseFridaPsTable(string(out))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(procs)
}

// handleFridaStart pushes frida-server and starts it on the connected device.
// With ?host=1 it only verifies the local frida CLI is present: no server
// push is needed for host-side attach.
func handleFridaStart(w http.ResponseWriter, r *http.Request) {
	if fridaTargetHost(r) {
		if findFridaCLI() == "" {
			http.Error(w, "frida CLI not found — pip install frida-tools", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"ok":true}`)
		return
	}
	serial := web.LiveSerial()
	if serial == "" {
		http.Error(w, "no device", http.StatusNotFound)
		return
	}
	adb := web.LiveADB()
	if err := pushAndStartFridaServer(adb, serial); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"ok":true}`)
}

// handleFridaREPL upgrades to WebSocket and bridges stdin/stdout to a live Frida session
// USB attach (-U) on Android, local attach on the host (?host=1).
func handleFridaREPL(w http.ResponseWriter, r *http.Request) {
	pidStr := r.URL.Query().Get("pid")
	if pidStr == "" {
		http.Error(w, "pid required", http.StatusBadRequest)
		return
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}

	host := fridaTargetHost(r)
	if !host {
		serial := web.LiveSerial()
		if serial == "" {
			http.Error(w, "no device", http.StatusNotFound)
			return
		}
	}
	frida := findFridaCLI()
	if frida == "" {
		http.Error(w, "frida not found", http.StatusServiceUnavailable)
		return
	}

	conn, _, _, err := wsx.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Spawn frida REPL process (local attach on host, USB on Android).
	cmd := exec.CommandContext(ctx, frida, fridaReplArgs(host, pidStr)...)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		wsx.WriteServerText(conn, []byte("error: "+err.Error()+"\n")) //nolint:errcheck
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		wsx.WriteServerText(conn, []byte("error: "+err.Error()+"\n")) //nolint:errcheck
		return
	}
	cmd.Stderr = cmd.Stdout // merge stderr

	if err := cmd.Start(); err != nil {
		wsx.WriteServerText(conn, []byte("error starting frida: "+err.Error()+"\n")) //nolint:errcheck
		return
	}
	defer func() {
		cancel()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Goroutine: frida stdout → WebSocket.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				if werr := wsx.WriteServerText(conn, buf[:n]); werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// Main loop: WebSocket → frida stdin.
	for {
		msg, _, err := wsx.ReadClientData(conn)
		if err != nil {
			return
		}
		// A blank message is treated as Ctrl-D / EOF (detach).
		if len(strings.TrimSpace(string(msg))) == 0 {
			stdinPipe.Close() //nolint:errcheck
			return
		}
		line := string(msg)
		if !strings.HasSuffix(line, "\n") {
			line += "\n"
		}
		if _, err := io.WriteString(stdinPipe, line); err != nil {
			return
		}
		// Check if context was cancelled by the stdout goroutine.
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// handleFridaRepackAPK repacks an APK by injecting Frida Gadget so it works
// on non-rooted devices.  The result is a re-signed APK saved next to the
// original with a ".frida.apk" suffix.
//
// Requirements (all checked at runtime):
//   - apktool.jar on PATH or Desktop/Downloads
//   - java on PATH
//   - apksigner on PATH or in the Android SDK
//   - frida-gadget-*-android-arm64.so (or matching ABI) on Desktop/Downloads
func handleFridaRepackAPK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		APKPath string `json:"apk_path"`
		ABI     string `json:"abi"` // arm64, arm, x86, x86_64
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.APKPath == "" {
		http.Error(w, "apk_path required", http.StatusBadRequest)
		return
	}
	if req.ABI == "" {
		req.ABI = "arm64"
	}

	w.Header().Set("Content-Type", "application/json")
	out, err := injectFridaGadget(req.APKPath, req.ABI)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"output_apk": out})
}

// injectFridaGadget does the actual APK repack to inject Frida Gadget.
func injectFridaGadget(apkPath, abi string) (string, error) {
	// Find tools.
	java, err := exec.LookPath("java")
	if err != nil {
		return "", fmt.Errorf("java not found on PATH")
	}
	apktool := findApktool()
	if apktool == "" {
		return "", fmt.Errorf("apktool.jar not found (place it on Desktop or Downloads)")
	}
	gadgetSO := findFridaGadget(abi)
	if gadgetSO == "" {
		return "", fmt.Errorf("frida-gadget-*-android-%s.so not found (place it on Desktop or Downloads)", abi)
	}
	apksigner := findApkSigner()
	if apksigner == "" {
		return "", fmt.Errorf("apksigner not found (install Android SDK build-tools or place apksigner on PATH)")
	}

	// Work in a temp dir.
	tmpDir, err := os.MkdirTemp("", "frida_repack_*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	decodedDir := filepath.Join(tmpDir, "decoded")

	// 1. Decode APK.
	if out, err := runTool(10*time.Minute, java, "-jar", apktool, "d", "-f", "-o", decodedDir, apkPath); err != nil {
		return "", fmt.Errorf("apktool decode: %w — %s", err, out)
	}

	// 2. Inject gadget SO.
	libABIDir := filepath.Join(decodedDir, "lib", abiDir(abi))
	_ = os.MkdirAll(libABIDir, 0755)
	gadgetDest := filepath.Join(libABIDir, "libfrida-gadget.so")
	if err := copyFile(gadgetSO, gadgetDest); err != nil {
		return "", fmt.Errorf("copy gadget SO: %w", err)
	}

	// 3. Write gadget config next to it so it acts as a server (listens on 27042).
	gadgetCfg := `{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_load":"wait"}}`
	if err := os.WriteFile(filepath.Join(libABIDir, "libfrida-gadget.config.so"), []byte(gadgetCfg), 0644); err != nil {
		return "", err
	}

	// 4. Rebuild APK.
	rebuiltAPK := filepath.Join(tmpDir, "rebuilt.apk")
	if out, err := runTool(10*time.Minute, java, "-jar", apktool, "b", "-o", rebuiltAPK, decodedDir); err != nil {
		return "", fmt.Errorf("apktool build: %w — %s", err, out)
	}

	// 5. Re-sign with a debug keystore (creates one if absent).
	keystore := filepath.Join(os.TempDir(), "frida_debug.jks")
	if _, err := os.Stat(keystore); os.IsNotExist(err) {
		kargs := []string{
			"-genkeypair", "-v",
			"-keystore", keystore,
			"-alias", "frida",
			"-keyalg", "RSA", "-keysize", "2048",
			"-validity", "9125",
			"-dname", "CN=FridaDebug,O=FridaDebug,C=US",
			"-storepass", "fridadebug",
			"-keypass", "fridadebug",
		}
		java2, _ := exec.LookPath("keytool")
		if java2 == "" {
			java2 = strings.Replace(java, "java", "keytool", 1)
		}
		if _, err := runTool(2*time.Minute, java2, kargs...); err != nil {
			return "", fmt.Errorf("keytool: %w", err)
		}
	}

	outAPK := strings.TrimSuffix(apkPath, ".apk") + ".frida.apk"
	signArgs := []string{
		"sign",
		"--ks", keystore,
		"--ks-pass", "pass:fridadebug",
		"--ks-key-alias", "frida",
		"--key-pass", "pass:fridadebug",
		"--in", rebuiltAPK,
		"--out", outAPK,
	}
	if out, err := runTool(5*time.Minute, apksigner, signArgs...); err != nil {
		return "", fmt.Errorf("apksigner: %w — %s", err, out)
	}

	return outAPK, nil
}

// abiDir maps frida ABI names to Android lib directory names.
func abiDir(abi string) string {
	switch abi {
	case "arm64":
		return "arm64-v8a"
	case "arm":
		return "armeabi-v7a"
	case "x86":
		return "x86"
	case "x86_64":
		return "x86_64"
	}
	return abi
}

func findApktool() string {
	if p, err := exec.LookPath("apktool"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	for _, base := range []string{filepath.Join(home, "Desktop"), filepath.Join(home, "Downloads"), home} {
		entries, _ := os.ReadDir(base)
		for _, e := range entries {
			if !e.IsDir() && (e.Name() == "apktool.jar" || strings.HasPrefix(e.Name(), "apktool_")) {
				return filepath.Join(base, e.Name())
			}
		}
	}
	return ""
}

func findFridaGadget(abi string) string {
	home, _ := os.UserHomeDir()
	for _, base := range []string{filepath.Join(home, "Desktop"), filepath.Join(home, "Downloads"), home} {
		entries, _ := os.ReadDir(base)
		for _, e := range entries {
			n := e.Name()
			if !e.IsDir() && strings.HasPrefix(n, "frida-gadget") && strings.Contains(n, abi) && strings.HasSuffix(n, ".so") {
				return filepath.Join(base, n)
			}
		}
	}
	return ""
}

func findApkSigner() string {
	if p, err := exec.LookPath("apksigner"); err == nil {
		return p
	}
	// Try Android SDK build-tools.
	home, _ := os.UserHomeDir()
	sdkRoot := filepath.Join(home, "AppData", "Local", "Android", "Sdk")
	if runtime.GOOS != "windows" {
		sdkRoot = filepath.Join(home, "Android", "Sdk")
	}
	btDir := filepath.Join(sdkRoot, "build-tools")
	if entries, err := os.ReadDir(btDir); err == nil {
		for i := len(entries) - 1; i >= 0; i-- { // newest first
			e := entries[i]
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(btDir, e.Name(), "apksigner")
			if runtime.GOOS == "windows" {
				p += ".bat"
			}
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
