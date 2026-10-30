package main

import (
	"testing"

	"mega-analyzer/pkg/vulnscan"
)

func TestCLIParsesWebScanModes(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{
		"--web-scan",
		"--web-scan-target", "https://example.test",
		"--web-scan-mode", "status",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatal(err)
	}
	if opts.WebScanMode != string(vulnscan.ScanModeStatus) {
		t.Fatalf("mode = %q, want status", opts.WebScanMode)
	}
}

func TestCLIRejectsInvalidOrLabSafeMode(t *testing.T) {
	bad := &CLIOptions{WebScan: true, WebScanTarget: "https://example.test", WebScanMode: "everything"}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected invalid mode error")
	}

	lab := &CLIOptions{
		WebScan:        true,
		WebScanTarget:  "https://example.test",
		WebScanMode:    "passive",
		WebScanLabMode: true,
	}
	if err := lab.Validate(); err == nil {
		t.Fatal("expected lab-mode/passive validation error")
	}
}
