package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// mitmproxy live HTTP(S) interception. When the user opts in (the "HTTPS
// interception" checkbox), we run mitmdump on the host, point the device's
// global HTTP proxy at it, and stream every decrypted request to the dashboard
// as `http` telemetry events in real time.
//
// HTTPS requires the mitmproxy CA certificate to be trusted on the device
// (one-time manual step). Plaintext HTTP works without it. We surface a clear
// hint either way so the user knows what to expect.

const mitmAddonScript = `
import json, sys
def response(flow):
    try:
        sys.stdout.write(json.dumps({
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "host": flow.request.host,
        }) + "\n")
        sys.stdout.flush()
    except Exception:
        pass
`

// liveMitmMonitor runs mitmdump + device proxy and emits live http events until
// stop is closed. Best-effort: logs and returns cleanly if mitmdump is absent.
func liveMitmMonitor(emit func(TelemetryEvent), adb, serial string, stop <-chan struct{}) {
	if adb == "" || serial == "" {
		return
	}
	mitmdump, err := exec.LookPath("mitmdump")
	if err != nil {
		emit(TelemetryEvent{Type: "status", Process: "mitmproxy", Details: "mitmproxy not installed — skipping HTTPS interception (pip install mitmproxy)"})
		return
	}

	// Host address the device should use as its proxy.
	proxyHost := "10.0.2.2"
	if !strings.HasPrefix(serial, "emulator-") {
		proxyHost = hostLANIP()
		if proxyHost == "" {
			emit(TelemetryEvent{Type: "status", Process: "mitmproxy", Details: "mitmproxy: no host LAN IP found — skipping"})
			return
		}
	}
	const proxyPort = 8080

	// Write the streaming addon to a temp file.
	scriptFile, err := os.CreateTemp("", "mitm-addon-*.py")
	if err != nil {
		emit(TelemetryEvent{Type: "status", Process: "mitmproxy", Details: "mitmproxy setup failed: " + err.Error()})
		return
	}
	scriptPath := scriptFile.Name()
	_, _ = scriptFile.WriteString(mitmAddonScript)
	_ = scriptFile.Close()
	defer os.Remove(scriptPath)

	cmd := exec.Command(mitmdump, "-p", strconv.Itoa(proxyPort), "-q", "-s", scriptPath, "--ssl-insecure")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		emit(TelemetryEvent{Type: "status", Process: "mitmproxy", Details: "mitmproxy failed to start: " + err.Error()})
		return
	}
	go cmd.Wait() // reap the child; exit status is not needed here

	// Wait until the proxy actually accepts connections instead of sleeping
	// and hoping. If it never binds (port busy, crash), do not point the
	// device at a proxy that is not ours.
	bound := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(proxyPort), 250*time.Millisecond); err == nil {
			c.Close()
			bound = true
			break
		}
	}
	if !bound {
		emit(TelemetryEvent{Type: "status", Process: "mitmproxy", Details: "mitmproxy did not bind port 8080 (busy or crashed) — skipping HTTPS interception"})
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return
	}

	// Point the device at our proxy.
	_, _ = runADB(adb, serial, 15*time.Second, "shell", "settings", "put", "global", "http_proxy", fmt.Sprintf("%s:%d", proxyHost, proxyPort))
	emit(TelemetryEvent{Type: "status", Process: "mitmproxy", Details: fmt.Sprintf("mitmproxy intercepting → %s:%d (install its CA cert on the device to decrypt HTTPS)", proxyHost, proxyPort)})

	// Clean up: clear the proxy and kill mitmdump on stop.
	cleanup := func() {
		_, _ = runADB(adb, serial, 15*time.Second, "shell", "settings", "put", "global", "http_proxy", ":0")
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	go func() {
		<-stop
		cleanup()
	}()

	// Stream each decrypted request line as an http event.
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var f struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Status int    `json:"status"`
			Host   string `json:"host"`
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			continue
		}
		emit(TelemetryEvent{
			Type:   "http",
			Method: f.Method,
			URL:    f.URL,
			Status: strconv.Itoa(f.Status),
			Host:   f.Host,
		})
	}
	cleanup()
}

// runADBOut is the stdout-only adb-shell variant used by the telemetry
// poll loop, which runs every tick and must never block indefinitely on
// a hung device. (Combined-output calls go through runADB in live_frida.go;
// this one stays separate so poll parsing never ingests stderr.)
func runADBOut(adb, serial string, timeout time.Duration, shellArgs ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args := append([]string{"-s", serial, "shell"}, shellArgs...)
	return exec.CommandContext(ctx, adb, args...).Output()
}
