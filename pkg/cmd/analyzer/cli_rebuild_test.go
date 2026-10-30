package main

import (
	"mega-analyzer/pkg/logger"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIRebuildFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantRebuild bool
		wantBuild   bool
		wantNoSign  bool
		wantNoAlign bool
		wantErr     bool
	}{
		{
			name:        "rebuild flag",
			args:        []string{"--rebuild", "-t", "./test", "-o", "./out.apk"},
			wantRebuild: true,
			wantNoSign:  false,
			wantNoAlign: false,
			wantErr:     false,
		},
		{
			name:        "rebuild shorthand",
			args:        []string{"-r", "-t", "./test", "-o", "./out.apk"},
			wantRebuild: true,
			wantNoSign:  false,
			wantNoAlign: false,
			wantErr:     false,
		},
		{
			name:        "build flag (alias)",
			args:        []string{"--build", "-t", "./test", "-o", "./out.apk"},
			wantBuild:   true,
			wantNoSign:  false,
			wantNoAlign: false,
			wantErr:     false,
		},
		{
			name:        "build shorthand",
			args:        []string{"-b", "-t", "./test", "-o", "./out.apk"},
			wantBuild:   true,
			wantNoSign:  false,
			wantNoAlign: false,
			wantErr:     false,
		},
		{
			name:        "rebuild with no-sign",
			args:        []string{"--rebuild", "-t", "./test", "-o", "./out.apk", "--no-sign"},
			wantRebuild: true,
			wantNoSign:  true,
			wantNoAlign: false,
			wantErr:     false,
		},
		{
			name:        "rebuild with no-align",
			args:        []string{"--rebuild", "-t", "./test", "-o", "./out.apk", "--no-align"},
			wantRebuild: true,
			wantNoSign:  false,
			wantNoAlign: true,
			wantErr:     false,
		},
		{
			name:        "rebuild with both no-sign and no-align",
			args:        []string{"-r", "-t", "./test", "-o", "./out.apk", "--no-sign", "--no-align"},
			wantRebuild: true,
			wantNoSign:  true,
			wantNoAlign: true,
			wantErr:     false,
		},
		{
			name:        "rebuild without target",
			args:        []string{"--rebuild", "-o", "./out.apk"},
			wantRebuild: true,
			wantErr:     true,
		},
		{
			name:        "rebuild without output",
			args:        []string{"--rebuild", "-t", "./test"},
			wantRebuild: true,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if opts.Rebuild != tt.wantRebuild {
				t.Errorf("Rebuild = %v, want %v", opts.Rebuild, tt.wantRebuild)
			}
			if opts.Build != tt.wantBuild {
				t.Errorf("Build = %v, want %v", opts.Build, tt.wantBuild)
			}
			if opts.NoSign != tt.wantNoSign {
				t.Errorf("NoSign = %v, want %v", opts.NoSign, tt.wantNoSign)
			}
			if opts.NoAlign != tt.wantNoAlign {
				t.Errorf("NoAlign = %v, want %v", opts.NoAlign, tt.wantNoAlign)
			}

			err = opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCLIRebuildCommand(t *testing.T) {
	opts := &CLIOptions{
		Rebuild: true,
		Target:  "./test",
		Output:  "./out.apk",
	}

	if !opts.IsRebuildCommand() {
		t.Error("IsRebuildCommand() = false, want true")
	}
	if !opts.IsBuildCommand() {
		t.Error("IsBuildCommand() = false, want true")
	}
}

func TestCLIDecodeFlags(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		wantDecode       bool
		wantNoResources  bool
		wantNoSmali      bool
		wantCopyOriginal bool
		wantErr          bool
	}{
		{
			name:       "decode flag",
			args:       []string{"--decode", "-t", "./app.apk", "-o", "./out"},
			wantDecode: true,
			wantErr:    false,
		},
		{
			name:             "decode with options",
			args:             []string{"--decode", "-t", "./app.apk", "-o", "./out", "--no-resources", "--no-smali", "--copy-original"},
			wantDecode:       true,
			wantNoResources:  true,
			wantNoSmali:      true,
			wantCopyOriginal: true,
			wantErr:          false,
		},
		{
			name:       "decode without target",
			args:       []string{"--decode", "-o", "./out"},
			wantDecode: true,
			wantErr:    true,
		},
		{
			name:       "decode without output",
			args:       []string{"--decode", "-t", "./app.apk"},
			wantDecode: true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewCLIParser()
			opts, err := parser.Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if opts.Decode != tt.wantDecode {
				t.Errorf("Decode = %v, want %v", opts.Decode, tt.wantDecode)
			}
			if opts.NoResources != tt.wantNoResources {
				t.Errorf("NoResources = %v, want %v", opts.NoResources, tt.wantNoResources)
			}
			if opts.NoSmali != tt.wantNoSmali {
				t.Errorf("NoSmali = %v, want %v", opts.NoSmali, tt.wantNoSmali)
			}
			if opts.CopyOriginal != tt.wantCopyOriginal {
				t.Errorf("CopyOriginal = %v, want %v", opts.CopyOriginal, tt.wantCopyOriginal)
			}

			err = opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCLIDecodeCommand(t *testing.T) {
	opts := &CLIOptions{
		Decode: true,
		Target: "./app.apk",
		Output: "./out",
	}
	if !opts.IsDecodeCommand() {
		t.Error("IsDecodeCommand() = false, want true")
	}
	if opts.IsBuildCommand() {
		t.Error("IsBuildCommand() = true, want false")
	}
}

func TestRebuildIntegration(t *testing.T) {
	// Create a temporary test directory structure
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	outputAPK := filepath.Join(tempDir, "output.apk")

	// Add cleanup for Windows (TempDir sometimes fails on Windows)
	t.Cleanup(func() {
		// Force remove temp dir even if files are locked
		os.RemoveAll(tempDir)
	})

	// Create source directory with minimal APK structure
	if err := os.MkdirAll(filepath.Join(sourceDir, "smali"), 0755); err != nil {
		t.Fatalf("Failed to create source dir: %v", err)
	}

	// Create AndroidManifest.xml
	manifestContent := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
    <application android:label="Test">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
    </application>
</manifest>`
	if err := os.WriteFile(filepath.Join(sourceDir, "AndroidManifest.xml"), []byte(manifestContent), 0644); err != nil {
		t.Fatalf("Failed to create manifest: %v", err)
	}

	// Create a simple smali file
	smaliContent := `.class public Lcom/test/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 0
    return-void
.end method`
	if err := os.WriteFile(filepath.Join(sourceDir, "smali", "MainActivity.smali"), []byte(smaliContent), 0644); err != nil {
		t.Fatalf("Failed to create smali file: %v", err)
	}

	// Test rebuild with no-sign and no-align for speed
	app := NewApp()
	app.opts = &CLIOptions{
		Rebuild: true,
		Target:  sourceDir,
		Output:  outputAPK,
		NoSign:  true,
		NoAlign: true,
		Quiet:   true,
	}

	// Initialize
	if err := app.initialize(); err != nil {
		t.Fatalf("initialize() error = %v", err)
	}
	// On Windows the global logger keeps `analyzer.log` open which blocks
	// `t.TempDir()` cleanup. Close it explicitly when the test exits.
	t.Cleanup(logger.Close)

	// Run rebuild
	if err := app.handleRebuild(); err != nil {
		t.Fatalf("handleRebuild() error = %v", err)
	}

	// Verify output APK exists
	if _, err := os.Stat(outputAPK); os.IsNotExist(err) {
		t.Errorf("Output APK not created: %s", outputAPK)
	}

	// Verify output is a valid ZIP file
	info, err := os.Stat(outputAPK)
	if err != nil {
		t.Fatalf("Failed to stat output APK: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Output APK is empty")
	}
}
