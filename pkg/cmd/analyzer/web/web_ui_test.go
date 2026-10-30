package web

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStripANSI(t *testing.T) {
	input := "\x1b[31mError\x1b[0m"
	expected := "Error"
	if stripANSI(input) != expected {
		t.Errorf("Expected %s, got %s", expected, stripANSI(input))
	}
}

func TestIsSafeArg(t *testing.T) {
	tests := []struct {
		in   string
		safe bool
	}{
		{"", false},
		{"-callgraph", true},
		{"123", true},
		{"Europe/Moscow", true},
		{"foo;rm -rf /", false},
		{"foo|bar", false},
		{"foo&bar", false},
	}
	for _, tt := range tests {
		if isSafeArg(tt.in) != tt.safe {
			t.Errorf("isSafeArg(%q) = %v, want %v", tt.in, !tt.safe, tt.safe)
		}
	}
}

func TestIsDigits(t *testing.T) {
	if isDigits("") {
		t.Error("empty should be false")
	}
	if isDigits("123456") {
		t.Error(">5 chars should be false")
	}
	if !isDigits("123") {
		t.Error("123 should be true")
	}
	if isDigits("12a") {
		t.Error("12a should be false")
	}
}

func TestIsSafeHostPort(t *testing.T) {
	if isSafeHostPort("") {
		t.Error("empty should be false")
	}
	if !isSafeHostPort("127.0.0.1:9339") {
		t.Error("127.0.0.1:9339 should be true")
	}
	if isSafeHostPort("127.0.0.1:9339;rm") {
		t.Error("semicolon should be false")
	}
}

func TestIsSafeURL(t *testing.T) {
	if !isSafeURL("http://example.com") {
		t.Error("http://example.com should be true")
	}
	if isSafeURL("ftp://example.com") {
		t.Error("ftp should be false")
	}
	if isSafeURL("http://example.com/ foo") {
		t.Error("space should be false")
	}
}

func TestIsSafeOutputPath(t *testing.T) {
	if !isSafeOutputPath("/path/to/file") {
		t.Error("normal path should be true")
	}
	if !isSafeOutputPath(`C:\Users\me\out`) {
		t.Error("windows path should be true")
	}
	if isSafeOutputPath("") {
		t.Error("empty should be false")
	}
	if isSafeOutputPath("/path/to/file\n") {
		t.Error("newline should be false")
	}
	if isSafeOutputPath("/path/to/file\x00") {
		t.Error("null byte should be false")
	}
	if isSafeOutputPath("/path/to/file\t") {
		t.Error("tab should be false")
	}
	if isSafeOutputPath(strings.Repeat("a", 4097)) {
		t.Error("overlong path should be false")
	}
}

func TestBuildModeArgs(t *testing.T) {
	args := buildModeArgs("decode", []string{"target.apk"}, "out", "", "", "", nil)
	if len(args) < 4 || args[0] != "-decode" {
		t.Errorf("bad args: %v", args)
	}

	args = buildModeArgs("web-scan", nil, "", "http://foo", "", "", nil)
	if len(args) < 2 || args[0] != "-web-scan" || args[1] != "-web-scan-target" || args[2] != "http://foo" {
		t.Errorf("bad args for web-scan: %v", args)
	}
}

func TestWebUI_Endpoints(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_NO_BROWSER", "1")

	port := 18888

	// Start server in background
	go func() {
		_ = runWebUI(port)
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	endpoints := []string{
		"/",
		"/sandbox",
		"/mitm",
		"/scan",
		"/api/pkg-version",
		"/api/env",
		"/api/live/status",
		"/api/live/screen",
		"/api/live/frida/status",
		"/api/tools/vbox",
		"/api/badge/counts",
	}

	for _, ep := range endpoints {
		resp, err := http.Get(baseURL + ep)
		if err != nil {
			t.Logf("Warning: GET %s failed: %v", ep, err)
			continue
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	}

	// Try a POST request
	req, _ := http.NewRequest("POST", baseURL+"/api/live/input", strings.NewReader(`{"type":"click","x":100,"y":100}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	reqMeta, _ := http.NewRequest("POST", baseURL+"/api/meta", strings.NewReader(`{"target":"nonexistent.apk"}`))
	reqMeta.Header.Set("Content-Type", "application/json")
	respMeta, err := http.DefaultClient.Do(reqMeta)
	if err == nil {
		io.Copy(io.Discard, respMeta.Body)
		respMeta.Body.Close()
	}

	// Stop job endpoint
	respStop, err := http.Get(baseURL + "/api/stop/12345")
	if err == nil {
		io.Copy(io.Discard, respStop.Body)
		respStop.Body.Close()
	}
}
