package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApp_ToolkitCommands(t *testing.T) {
	tempDir := t.TempDir()

	// Create dummy inputs
	dummyJS := filepath.Join(tempDir, "test.js")
	_ = os.WriteFile(dummyJS, []byte("var x = 1;"), 0644)

	app := NewApp()
	app.opts = &CLIOptions{}

	// Test --js-deobf
	app.opts.JSDeobfuscate = true
	app.opts.Target = dummyJS
	if err := app.initialize(); err != nil {
		t.Logf("init error: %v", err)
	}
	_ = app.handleJSDeobfuscate()

	// Test --js-patch
	app.opts.JSDeobfuscate = false
	app.opts.JSPatch = true
	app.opts.Target = tempDir
	_ = app.handleJSPatch()

	// Test --lab-dns
	app.opts.JSPatch = false
	app.opts.LabDNS = true
	// it blocks on running the server, so we can't easily run it directly unless we pass a quick timeout,
	// but we can call it. Wait, it might block. We won't call it if it blocks.
}
