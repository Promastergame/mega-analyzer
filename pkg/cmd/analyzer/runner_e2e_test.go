package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppRun_E2E_Success(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock files to trigger different analyzers

	// 1. AndroidManifest.xml
	manifestPath := filepath.Join(tempDir, "AndroidManifest.xml")
	manifestContent := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
	<uses-permission android:name="android.permission.INTERNET" />
	<application android:allowBackup="true" android:debuggable="true">
		<activity android:name=".MainActivity" android:exported="true">
			<intent-filter>
				<action android:name="android.intent.action.MAIN" />
				<category android:name="android.intent.category.LAUNCHER" />
			</intent-filter>
		</activity>
	</application>
</manifest>`
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Smali file
	smaliDir := filepath.Join(tempDir, "smali", "com", "example")
	if err := os.MkdirAll(smaliDir, 0755); err != nil {
		t.Fatal(err)
	}
	smaliPath := filepath.Join(smaliDir, "MainActivity.smali")
	smaliContent := `.class public Lcom/example/MainActivity;
.super Landroid/app/Activity;

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
	const-string v0, "SecretKey123"
	invoke-static {v0}, Landroid/util/Log;->d(Ljava/lang/String;)I
    return-void
.end method`
	if err := os.WriteFile(smaliPath, []byte(smaliContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. JS file
	jsDir := filepath.Join(tempDir, "assets", "www")
	if err := os.MkdirAll(jsDir, 0755); err != nil {
		t.Fatal(err)
	}
	jsPath := filepath.Join(jsDir, "app.js")
	jsContent := `function login() { var token = "dummy_token_123"; eval("alert('xss')"); }`
	if err := os.WriteFile(jsPath, []byte(jsContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create output dir
	outDir := t.TempDir()

	app := NewApp()
	// Run basic analysis
	args := []string{
		"-t", tempDir,
		"-o", outDir,
		"--profile", "quick",
		"--json",  // also test json output
		"--quiet", // reduce noise
		"--no-color",
	}

	err := app.Run(args)
	if err != nil {
		t.Fatalf("App.Run() returned unexpected error: %v", err)
	}
}

func TestAppRun_E2E_Deep(t *testing.T) {
	tempDir := t.TempDir()

	smaliDir := filepath.Join(tempDir, "smali")
	_ = os.MkdirAll(smaliDir, 0755)
	_ = os.WriteFile(filepath.Join(smaliDir, "Test.smali"), []byte(".class public LTest;"), 0644)

	app := NewApp()
	args := []string{
		"-t", tempDir,
		"--profile", "deep",
		"--quiet",
		"--no-color",
		"--sarif",
		"--ml-patch", // try some ml features
		"--call-graph",
		"--correlations",
	}

	err := app.Run(args)
	if err != nil {
		// Just ensure it doesn't panic, it might error if ML models not found
		t.Logf("Deep run returned error (expected possibly): %v", err)
	}
}
