package apkloader

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewAPKRebuilder(t *testing.T) {
	rebuilder := NewAPKRebuilder("/test/path")

	if rebuilder.SourceDir != "/test/path" {
		t.Errorf("expected SourceDir=/test/path, got %s", rebuilder.SourceDir)
	}

	if !rebuilder.IncludeSignature {
		t.Error("expected IncludeSignature=true by default")
	}

	if !rebuilder.IncludeAlignment {
		t.Error("expected IncludeAlignment=true by default")
	}
}

func TestShouldCompressFile(t *testing.T) {
	rebuilder := NewAPKRebuilder("")

	tests := []struct {
		path     string
		compress bool
	}{
		// dex and native libs are deflated (apktool 3.x does the same, ~3x
		// smaller); only arsc and already-compressed media stay stored.
		{"classes.dex", true},
		{"classes2.dex", true},
		{"lib/armeabi/libtest.so", true},
		{"res/drawable/icon.png", false},     // .png is no-compress
		{"res/drawable/banner.9.png", false}, // 9-patch is no-compress
		{"res/drawable/bg.jpg", false},       // .jpg is no-compress
		{"assets/sound.mp3", false},          // .mp3 is no-compress
		{"resources.arsc", false},            // .arsc is no-compress
		// Everything else compresses
		{"assets/data.json", true},
		{"smali/com/example/Test.smali", true},
		{"AndroidManifest.xml", true},
		{"res/layout/main.xml", true}, // plain XML inside res compresses
		{"res/values/strings.xml", true},
	}

	for _, tt := range tests {
		result := rebuilder.shouldCompressFile(tt.path)
		if result != tt.compress {
			t.Errorf("shouldCompressFile(%s) = %v, want %v", tt.path, result, tt.compress)
		}
	}

	// Test custom doNotCompress from apktool.json
	rebuilder.meta = &APKMeta{DoNotCompress: []string{"custom", "data"}}
	if rebuilder.shouldCompressFile("assets/file.custom") != false {
		t.Error("custom doNotCompress extension should not compress")
	}
	if rebuilder.shouldCompressFile("assets/file.txt") != true {
		t.Error("txt should still compress when not in doNotCompress")
	}
}

func TestCollectFiles(t *testing.T) {
	// Create temporary directory structure
	tempDir, err := os.MkdirTemp("", "apk_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	testFiles := []string{
		"AndroidManifest.xml",
		"classes.dex",
		"smali/com/example/Test.smali",
		"res/values/strings.xml",
		"assets/data.json",
	}

	for _, file := range testFiles {
		fullPath := filepath.Join(tempDir, file)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte("test content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Test collection
	rebuilder := NewAPKRebuilder(tempDir)
	ctx := context.Background()

	files, err := rebuilder.collectFiles(ctx)
	if err != nil {
		t.Fatalf("collectFiles failed: %v", err)
	}

	// Smali sources must never ship inside the APK: they are build input,
	// DEX is the runtime artifact.
	want := len(testFiles) - 1 // minus smali/com/example/Test.smali
	if len(files) != want {
		t.Errorf("expected %d files (smali excluded), got %d", want, len(files))
	}
	for _, f := range files {
		if strings.HasSuffix(f.RelativePath, ".smali") {
			t.Errorf("smali source must not ship in APK: %s", f.RelativePath)
		}
	}

	// Verify file paths use forward slashes
	for _, file := range files {
		if filepath.Separator == '\\' && filepath.IsAbs(file.RelativePath) {
			t.Errorf("file path should be relative: %s", file.RelativePath)
		}
	}
}

func TestCollectFilesWithContext(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "apk_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a file
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	rebuilder := NewAPKRebuilder(tempDir)
	_, err = rebuilder.collectFiles(ctx)

	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestRebuildBasic(t *testing.T) {
	// Create temporary source directory
	tempDir, err := os.MkdirTemp("", "apk_source_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	manifest := filepath.Join(tempDir, "AndroidManifest.xml")
	if err := os.WriteFile(manifest, []byte("<?xml version=\"1.0\"?><manifest/>"), 0644); err != nil {
		t.Fatal(err)
	}

	dexFile := filepath.Join(tempDir, "classes.dex")
	if err := os.WriteFile(dexFile, []byte("dex\n035\x00"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create output path
	outputPath := filepath.Join(tempDir, "output.apk")

	// Rebuild without signing/alignment for faster test
	rebuilder := NewAPKRebuilder(tempDir)
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = false

	ctx := context.Background()
	if err := rebuilder.Rebuild(ctx, outputPath); err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	// Verify output exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("output APK was not created")
	}

	// Verify it's a valid ZIP
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("output is not a valid ZIP: %v", err)
	}
	defer reader.Close()

	// Verify files are present
	foundManifest := false
	foundDex := false

	for _, file := range reader.File {
		if file.Name == "AndroidManifest.xml" {
			foundManifest = true
		}
		if file.Name == "classes.dex" {
			foundDex = true
		}
	}

	if !foundManifest {
		t.Error("AndroidManifest.xml not found in output APK")
	}
	if !foundDex {
		t.Error("classes.dex not found in output APK")
	}
}

func TestRebuildCompression(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "apk_compress_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create files that should be compressed
	resDir := filepath.Join(tempDir, "res", "values")
	if err := os.MkdirAll(resDir, 0755); err != nil {
		t.Fatal(err)
	}

	resFile := filepath.Join(resDir, "strings.xml")
	content := []byte("<resources><string name=\"app_name\">Test</string></resources>")
	if err := os.WriteFile(resFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Create file that should NOT be compressed
	dexFile := filepath.Join(tempDir, "classes.dex")
	if err := os.WriteFile(dexFile, []byte("dex\n035\x00test"), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(tempDir, "output.apk")

	rebuilder := NewAPKRebuilder(tempDir)
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = false

	ctx := context.Background()
	if err := rebuilder.Rebuild(ctx, outputPath); err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	// Verify compression methods
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if file.Name == "res/values/strings.xml" {
			if file.Method != zip.Deflate {
				t.Errorf("res file should be compressed (Deflate), got method %d", file.Method)
			}
		}
		if file.Name == "classes.dex" {
			if file.Method != zip.Deflate {
				t.Errorf("dex file should be deflated, got method %d", file.Method)
			}
		}
	}
}

func TestRebuildPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	tempDir, err := os.MkdirTemp("", "apk_perf_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create many files to test performance
	for i := 0; i < 100; i++ {
		dir := filepath.Join(tempDir, "smali", "com", "example")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}

		file := filepath.Join(dir, fmt.Sprintf("Class%d.smali", i))
		content := []byte(".class public Lcom/example/Class" + fmt.Sprintf("%d", i) + ";\n.super Ljava/lang/Object;\n")
		if err := os.WriteFile(file, content, 0644); err != nil {
			t.Fatal(err)
		}
	}

	outputPath := filepath.Join(tempDir, "output.apk")

	// A real decode tree also ships the compiled dex + manifest alongside the
	// smali sources; those are what lands in the APK (smali never ships).
	if err := os.WriteFile(filepath.Join(tempDir, "classes.dex"), []byte("dex\n035\x00payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "AndroidManifest.xml"), []byte(`<?xml version="1.0"?><manifest/>`), 0o644); err != nil {
		t.Fatal(err)
	}

	rebuilder := NewAPKRebuilder(tempDir)
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = false

	ctx := context.Background()
	start := time.Now()

	if err := rebuilder.Rebuild(ctx, outputPath); err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	duration := time.Since(start)

	// Should complete reasonably fast (within 5 seconds for 100 files)
	if duration > 5*time.Second {
		t.Errorf("Rebuild took too long: %v", duration)
	}

	t.Logf("Rebuilt 100 files in %v", duration)
}

func TestRebuildEmptyDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "apk_empty_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	outputPath := filepath.Join(tempDir, "output.apk")

	rebuilder := NewAPKRebuilder(tempDir)
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = false

	ctx := context.Background()
	err = rebuilder.Rebuild(ctx, outputPath)

	if err == nil {
		t.Error("expected error for empty directory, got nil")
	}
}

func TestGetWarnings(t *testing.T) {
	rebuilder := NewAPKRebuilder("")

	if len(rebuilder.GetWarnings()) != 0 {
		t.Error("expected no warnings initially")
	}

	rebuilder.warn("test warning")

	warnings := rebuilder.GetWarnings()
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(warnings))
	}

	if warnings[0] != "test warning" {
		t.Errorf("expected 'test warning', got '%s'", warnings[0])
	}
}

func TestFrameworkAPKsParsing(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "apk_framework_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a mock apktool.yml
	ymlContent := `
usesFramework:
  ids:
    - 1
    - 12
  tag: mycustomtag
`
	if err := os.WriteFile(filepath.Join(tempDir, "apktool.yml"), []byte(ymlContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Mock framework folder
	mockFrameworkDir := filepath.Join(tempDir, "frameworks")
	if err := os.MkdirAll(mockFrameworkDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create mock .apk files
	if err := os.WriteFile(filepath.Join(mockFrameworkDir, "1.apk"), []byte("mock-apk"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mockFrameworkDir, "12-mycustomtag.apk"), []byte("mock-custom-apk"), 0644); err != nil {
		t.Fatal(err)
	}

	// Override LocalAppData env variable to point to our temp dir
	oldLocal := os.Getenv("LocalAppData")
	defer os.Setenv("LocalAppData", oldLocal)
	os.Setenv("LocalAppData", tempDir)

	// We want standard apktool directory hierarchy inside LocalAppData: LocalAppData/apktool/framework/
	apktoolFrameworkDir := filepath.Join(tempDir, "apktool", "framework")
	if err := os.MkdirAll(apktoolFrameworkDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Copy mock files to the correct place
	if err := os.WriteFile(filepath.Join(apktoolFrameworkDir, "1.apk"), []byte("mock-apk"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apktoolFrameworkDir, "12-mycustomtag.apk"), []byte("mock-custom-apk"), 0644); err != nil {
		t.Fatal(err)
	}

	rebuilder := NewAPKRebuilder(tempDir)
	frameworks := rebuilder.frameworkAPKs()

	// Should contain the mock 1.apk and 12-mycustomtag.apk
	found1 := false
	found12 := false
	for _, f := range frameworks {
		if filepath.Base(f) == "1.apk" {
			found1 = true
		}
		if filepath.Base(f) == "12-mycustomtag.apk" {
			found12 = true
		}
	}

	if !found1 {
		t.Error("expected 1.apk framework to be linked")
	}
	if !found12 {
		t.Error("expected 12-mycustomtag.apk framework to be linked")
	}
}
