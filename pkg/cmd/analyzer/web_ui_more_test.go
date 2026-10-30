package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestWebUI_WithMockADB compiles a mock adb executable, sets up the fake Android SDK
// environment, starts the WebUI server, and hits all endpoints to maximize coverage.
func TestWebUI_WithMockADB(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_NO_BROWSER", "1")

	tempDir := t.TempDir()

	// 1. Write and compile mock adb source code
	mockAdbSrc := filepath.Join(tempDir, "mock_adb.go")
	srcContent := `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	args := os.Args[1:]
	argStr := strings.Join(args, " ")

	if strings.Contains(argStr, "devices") {
		fmt.Println("List of devices attached")
		fmt.Println("emulator-5554\tdevice")
		return
	}
	if strings.Contains(argStr, "sys.boot_completed") {
		fmt.Println("1")
		return
	}
	if strings.Contains(argStr, "dumpsys power") {
		fmt.Println("Display Power: state=ON")
		return
	}
	if strings.Contains(argStr, "screencap -p") {
		os.Stdout.Write([]byte("\x89PNG\r\n\x1a\nFakePNGDataHereBytes"))
		return
	}
	if strings.Contains(argStr, "wm size") {
		fmt.Println("Physical size: 1080x1920")
		return
	}
	if strings.Contains(argStr, "pm list packages") {
		fmt.Println("package:com.example")
		return
	}
	if strings.Contains(argStr, "dumpsys package") {
		fmt.Println("versionName=1.2.3")
		return
	}
	if strings.Contains(argStr, "ro.product.model") {
		fmt.Println("Pixel 6 Mock")
		return
	}
	// default success exit
}
`
	if err := os.WriteFile(mockAdbSrc, []byte(srcContent), 0644); err != nil {
		t.Fatalf("failed to write mock adb source: %v", err)
	}

	// Compile mock adb
	adbName := "adb"
	if runtime.GOOS == "windows" {
		adbName = "adb.exe"
	}
	platformToolsDir := filepath.Join(tempDir, "platform-tools")
	if err := os.MkdirAll(platformToolsDir, 0755); err != nil {
		t.Fatalf("failed to create platform-tools dir: %v", err)
	}
	mockAdbBin := filepath.Join(platformToolsDir, adbName)

	cmd := exec.Command("go", "build", "-o", mockAdbBin, mockAdbSrc)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile mock adb: %v", err)
	}

	// 2. Set environment variables to point to the fake Android SDK
	t.Setenv("ANDROID_HOME", tempDir)
	t.Setenv("ANDROID_SDK_ROOT", tempDir)

	// 3. Start WebUI server in background on a random port
	port := 19999
	go func() {
		_ = runWebUI(port)
	}()

	// Give it some time to bind and listen
	time.Sleep(600 * time.Millisecond)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// 4. Hit all endpoints
	client := &http.Client{Timeout: 3 * time.Second}

	endpoints := []string{
		"/",
		"/sandbox",
		"/mitm",
		"/scan",
		"/api/pkg-version?pkg=com.example",
		"/api/pkg-version", // empty pkg
		"/api/env",
		"/api/live/status",
		"/api/live/screen",
		"/api/meta",
		"/api/live/frida/status",
		"/api/live/frida/processes",
		"/api/tools/vbox",
		"/api/badge/counts",
		"/api/stop/12345",
	}

	for _, ep := range endpoints {
		resp, err := client.Get(baseURL + ep)
		if err != nil {
			t.Logf("GET %s failed: %v", ep, err)
			continue
		}
		respBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("GET %s status: %d, len: %d", ep, resp.StatusCode, len(respBytes))
	}

	// Test POST /api/live/input for different actions
	inputActions := []string{
		`{"type":"tap","nx":0.5,"ny":0.5}`,
		`{"type":"longpress","nx":0.5,"ny":0.5,"dur":500}`,
		`{"type":"swipe","nx":0.2,"ny":0.2,"nx2":0.8,"ny2":0.8,"dur":200}`,
		`{"type":"key","key":"HOME"}`,
	}

	for _, action := range inputActions {
		req, _ := http.NewRequest("POST", baseURL+"/api/live/input", strings.NewReader(action))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			respBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Logf("POST input response: %s", string(respBytes))
		}
	}

	// Test GET /api/live/stream with a timeout/context to avoid hanging forever
	reqStream, _ := http.NewRequest("GET", baseURL+"/api/live/stream", nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()
	reqStream = reqStream.WithContext(ctx)

	respStream, err := client.Do(reqStream)
	if err == nil {
		// Read a bit and close
		buf := make([]byte, 1024)
		_, _ = respStream.Body.Read(buf)
		respStream.Body.Close()
	}

	// Shutdown server at the end of the test to allow clean file unlink on Windows
	activeServerMu.Lock()
	if activeServer != nil {
		_ = activeServer.Shutdown(context.Background())
		activeServer = nil
	}
	activeServerMu.Unlock()
}
