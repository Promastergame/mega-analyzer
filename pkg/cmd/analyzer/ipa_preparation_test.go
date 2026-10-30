package main

// Regression tests for the 2026-09-21 audit findings on IPA preparation:
// permission auditing must read the main app bundle's Info.plist (not the
// first Info.plist that a directory walk happens to hit, which can belong to
// an embedded framework), and the whole preparation must honour context
// cancellation.

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/config"
)

func writeTestIPA(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.ipa")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	entries := map[string]string{
		// The framework entry sorts before the app's own plist in a walk, so
		// the old first-hit plist selection audited the wrong bundle.
		"Payload/Main.app/Frameworks/SDK.framework/Info.plist": `<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>com.example.sdk</string></dict></plist>`,
		"Payload/Main.app/Info.plist":                          `<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>com.example.main</string><key>NSCameraUsageDescription</key><string>test</string></dict></plist>`,
	}
	for name, data := range entries {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractIPAAuditsMainBundlePlist(t *testing.T) {
	app := &App{opts: &CLIOptions{}, output: NewOutputWithWriter(NoColorTheme(), true, io.Discard)}
	dir, err := app.extractIPA(context.Background(), writeTestIPA(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for _, f := range app.ipaFindings {
		if strings.Contains(f.Reason, "NSCameraUsageDescription") {
			if f.Path != "Payload/Main.app/Info.plist" {
				t.Fatalf("camera finding attributed to %q, want the main bundle plist", f.Path)
			}
			return
		}
	}
	t.Fatalf("main app camera permission missing from findings: %+v", app.ipaFindings)
}

func TestPrepareTargetHonoursCancelledContext(t *testing.T) {
	app := &App{
		opts:   &CLIOptions{Target: writeTestIPA(t)},
		output: NewOutputWithWriter(NoColorTheme(), true, io.Discard),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir, err := app.prepareTarget(ctx, config.DefaultConfig())
	if dir != "" {
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	if err == nil {
		t.Fatal("IPA preparation succeeded with an already-cancelled context")
	}
	if app.tempDir != "" {
		t.Fatalf("cancelled preparation left temp dir %q registered", app.tempDir)
	}
}
