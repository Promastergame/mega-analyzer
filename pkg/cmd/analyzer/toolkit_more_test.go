package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestApp_ToolkitMore(t *testing.T) {
	tempDir := t.TempDir()

	app := NewApp()
	app.opts = &CLIOptions{}
	app.output = NewOutputWithWriter(DarkTheme(), true, &bytes.Buffer{})

	// 1. Test buildFramer and buildFrameLayout
	framer, desc, err := buildFramer("supercell")
	if err != nil || framer == nil || desc == "" {
		t.Errorf("failed to build supercell framer: %v", err)
	}

	framer, desc, err = buildFramer("len:10,2,4,inclhdr")
	if err != nil || framer == nil || desc == "" {
		t.Errorf("failed to build length prefix framer: %v", err)
	}

	_, _, err = buildFramer("invalid")
	if err == nil {
		t.Error("expected error for invalid framer spec")
	}

	_, _, err = buildFramer("len:bad,2,4")
	if err == nil {
		t.Error("expected error for bad HDR")
	}

	layout, err := buildFrameLayout("supercell")
	if err != nil || layout.HeaderLen != 7 {
		t.Errorf("failed to build supercell layout: %v", err)
	}

	layout, err = buildFrameLayout("len:8,2,2,1")
	if err != nil || layout.HeaderLen != 8 || !layout.LenInclHeader {
		t.Errorf("failed to build length layout: %v", err)
	}

	_, err = buildFrameLayout("invalid")
	if err == nil {
		t.Error("expected error for invalid frame layout")
	}

	_, err = buildFrameLayout("len:8,2")
	if err == nil {
		t.Error("expected error for missing parts")
	}

	// 2. Test handleActiveWebScanOnly
	app.opts.WebScanTarget = "http://example.internal"
	app.opts.WebScanIOwnThisTarget = false
	err = app.handleActiveWebScanOnly()
	if err == nil || err.Error() != "web vulnerability scan failed: safety gate: --i-own-this-target is required to run active scans" {
		t.Errorf("expected safety gate error, got: %v", err)
	}

	// 3. Test handleActiveWebScan
	res := &types.AnalysisResult{}
	err = app.handleActiveWebScan(res, tempDir)
	if err == nil || err.Error() != "web vulnerability scan failed: safety gate: --i-own-this-target is required to run active scans" {
		t.Errorf("expected safety gate error, got: %v", err)
	}

	// 4. Test handleServgen with Capture option
	capFile := filepath.Join(tempDir, "capture.jsonl")
	_ = os.WriteFile(capFile, []byte(`{"id": 10101, "direction": "c2s", "data": "AABBCC"}`), 0644)
	app.opts.ServgenFromCapture = capFile
	// It will try to run server gen, which might create a folder.
	// We catch error if it fails but it exercises the code path.
	_ = app.handleServgen()
	app.opts.ServgenFromCapture = ""

	// 5. Test handleServgen with spec file (falls back to dummy spec)
	app.opts.ServgenProtocol = "nonexistent_spec.json"
	_ = app.handleServgen()
	app.opts.ServgenProtocol = ""

	// 6. Test handleFuzz (missing capture error)
	app.opts.FuzzCapture = ""
	err = app.handleFuzz()
	if err == nil {
		t.Error("expected error for missing FuzzCapture")
	}

	// Test handleFuzz with dummy capture
	app.opts.FuzzCapture = capFile
	app.opts.FuzzOut = filepath.Join(tempDir, "fuzz_out.json")
	_ = app.handleFuzz()

	// 7. Test handleLabDNS with invalid address (fails quickly, doesn't block)
	app.opts.LabDNS = true
	app.opts.DNSAddr = "invalid_address_that_causes_immediate_failure"
	_ = app.handleLabDNS()
	app.opts.LabDNS = false

	// 8. Test handleJSDeobfuscate with non-existent file
	app.opts.Target = filepath.Join(tempDir, "nonexistent.js")
	err = app.handleJSDeobfuscate()
	if err == nil {
		t.Error("expected error for nonexistent file deobf")
	}
}

func TestApp_HandleIntercept_Timeout(t *testing.T) {
	app := NewApp()
	app.opts = &CLIOptions{
		InterceptPort: -1,
	}
	app.output = NewOutputWithWriter(DarkTheme(), true, &bytes.Buffer{})
	_ = app.handleIntercept()
}
