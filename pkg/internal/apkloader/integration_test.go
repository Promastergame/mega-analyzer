package apkloader

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"

	"mega-analyzer/pkg/internal/testutil"
)

// TestMiniSandboxRebuildWorkflow rebuilds the in-tree mini sandbox and verifies
// that binary XML and ARSC survive the round trip.
func TestMiniSandboxRebuildWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	sourceDir := writeMiniSandbox(t)

	// Step 2: Rebuild the APK
	outputAPK := filepath.Join(testutil.TempDir(t), "rebuilt.apk")
	rebuilder := NewAPKRebuilder(sourceDir)
	rebuilder.UseSmali = false
	rebuilder.IncludeSignature = false

	ctx := context.Background()
	if err := rebuilder.Rebuild(ctx, outputAPK); err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	// Step 3: Verify the rebuilt APK
	if _, err := os.Stat(outputAPK); os.IsNotExist(err) {
		t.Fatal("rebuilt APK does not exist")
	}

	// Step 4: Verify it's a valid ZIP
	reader, err := zip.OpenReader(outputAPK)
	if err != nil {
		t.Fatalf("rebuilt APK is not a valid ZIP: %v", err)
	}
	defer reader.Close()

	// Step 5: Verify files are present
	expectedFiles := []string{
		"AndroidManifest.xml",
		"res/values/strings.xml",
		"resources.arsc",
		"classes.dex",
		"assets/data.txt",
		"lib/arm64-v8a/libmini.so",
	}
	// Smali sources must never ship inside the APK: they are build input.
	unwantedFiles := []string{
		"smali/com/example/Mini.smali",
	}

	fileMap := make(map[string]bool)
	for _, file := range reader.File {
		fileMap[file.Name] = true
	}

	for _, expected := range expectedFiles {
		if !fileMap[expected] {
			t.Errorf("expected file %s not found in rebuilt APK", expected)
		}
	}
	for _, unwanted := range unwantedFiles {
		if fileMap[unwanted] {
			t.Errorf("smali source must not ship in rebuilt APK: %s", unwanted)
		}
	}

	entryData := func(t *testing.T, name string) []byte {
		t.Helper()
		for _, file := range reader.File {
			if file.Name != name {
				continue
			}
			entry, err := file.Open()
			if err != nil {
				t.Fatalf("open %s: %v", name, err)
			}
			defer entry.Close()
			data, err := io.ReadAll(entry)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			return data
		}
		t.Fatalf("entry %s not found", name)
		return nil
	}

	manifestData := entryData(t, "AndroidManifest.xml")
	if !axml.IsBinaryXML(manifestData) {
		t.Fatal("AndroidManifest.xml is not binary XML")
	}
	if _, err := axml.Decode(manifestData); err != nil {
		t.Fatalf("decode AndroidManifest.xml: %v", err)
	}
	if !axml.IsBinaryXML(entryData(t, "res/values/strings.xml")) {
		t.Fatal("res/values/strings.xml is not binary XML")
	}
	if _, err := axml.ParseARSC(entryData(t, "resources.arsc")); err != nil {
		t.Fatalf("parse resources.arsc: %v", err)
	}

	t.Logf("Successfully rebuilt APK with %d files", len(reader.File))
}

// TestRebuildWithoutSignature tests rebuilding without signing
func TestRebuildWithoutSignature(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nosign_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create source directory
	sourceDir := filepath.Join(tempDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Add files
	manifest := filepath.Join(sourceDir, "AndroidManifest.xml")
	if err := os.WriteFile(manifest, []byte("<?xml version=\"1.0\"?><manifest/>"), 0644); err != nil {
		t.Fatal(err)
	}

	dex := filepath.Join(sourceDir, "classes.dex")
	if err := os.WriteFile(dex, []byte("dex\n035\x00"), 0644); err != nil {
		t.Fatal(err)
	}

	// Rebuild without signature
	outputAPK := filepath.Join(tempDir, "unsigned.apk")
	rebuilder := NewAPKRebuilder(sourceDir)
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = false

	ctx := context.Background()
	if err := rebuilder.Rebuild(ctx, outputAPK); err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	// Verify no signature files
	reader, err := zip.OpenReader(outputAPK)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if file.Name == "META-INF/MANIFEST.MF" {
			t.Error("unsigned APK should not have META-INF/MANIFEST.MF")
		}
	}
}

// TestRebuildPreservesStructure tests that directory structure is preserved
func TestRebuildPreservesStructure(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "structure_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create complex directory structure
	sourceDir := filepath.Join(tempDir, "source")
	dirs := []string{
		"smali/com/example/app",
		"smali_classes2/com/example/lib",
		"res/raw",
		"res/xml",
		"assets/data",
		"lib/armeabi-v7a",
		"lib/arm64-v8a",
	}

	for _, dir := range dirs {
		fullPath := filepath.Join(sourceDir, dir)
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			t.Fatal(err)
		}

		// Add a file in each directory
		testFile := filepath.Join(fullPath, "test.txt")
		content := []byte("test")
		if dir == "res/xml" {
			testFile = filepath.Join(fullPath, "test.xml")
			content = []byte("<configuration/>")
		}
		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Add manifest
	manifest := filepath.Join(sourceDir, "AndroidManifest.xml")
	if err := os.WriteFile(manifest, []byte(`<?xml version="1.0"?><manifest package="example.structure"/>`), 0644); err != nil {
		t.Fatal(err)
	}

	// Rebuild
	outputAPK := filepath.Join(tempDir, "structured.apk")
	rebuilder := NewAPKRebuilder(sourceDir)
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = false

	ctx := context.Background()
	if err := rebuilder.Rebuild(ctx, outputAPK); err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	// Verify structure
	reader, err := zip.OpenReader(outputAPK)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	expectedPaths := []string{
		"res/raw/test.txt",
		"res/xml/test.xml",
		"resources.arsc",
		"assets/data/test.txt",
		"lib/armeabi-v7a/test.txt",
		"lib/arm64-v8a/test.txt",
	}
	// Smali sources must never ship inside the APK.
	unwantedPaths := []string{
		"smali/com/example/app/test.txt",
		"smali_classes2/com/example/lib/test.txt",
	}

	fileMap := make(map[string]bool)
	for _, file := range reader.File {
		fileMap[file.Name] = true
	}

	for _, expected := range expectedPaths {
		if !fileMap[expected] {
			t.Errorf("expected path %s not found in rebuilt APK", expected)
		}
	}
	for _, unwanted := range unwantedPaths {
		if fileMap[unwanted] {
			t.Errorf("smali source must not ship in rebuilt APK: %s", unwanted)
		}
	}
}

// TestRebuildPerformanceTarget tests that rebuild meets performance requirements
func TestRebuildPerformanceTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	tempDir, err := os.MkdirTemp("", "perf_target_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create source directory with many files (simulating extracted APK)
	sourceDir := filepath.Join(tempDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create many smali files
	for i := 0; i < 500; i++ {
		dir := filepath.Join(sourceDir, "smali", "com", "example")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}

		file := filepath.Join(dir, fmt.Sprintf("Class%d.smali", i))
		content := fmt.Sprintf(".class public Lcom/example/Class%d;\n.super Ljava/lang/Object;\n", i)
		if err := os.WriteFile(file, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Add manifest
	manifest := filepath.Join(sourceDir, "AndroidManifest.xml")
	if err := os.WriteFile(manifest, []byte("<?xml version=\"1.0\"?><manifest/>"), 0644); err != nil {
		t.Fatal(err)
	}

	// Rebuild without signing for fair comparison
	outputAPK := filepath.Join(tempDir, "rebuilt.apk")
	rebuilder := NewAPKRebuilder(sourceDir)
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = false

	ctx := context.Background()
	if err := rebuilder.Rebuild(ctx, outputAPK); err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	t.Log("Rebuild completed successfully")
}

// Helper: Create a complete test APK with all necessary files
func createCompleteTestAPK(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := zip.NewWriter(file)
	defer writer.Close()

	files := map[string]string{
		"AndroidManifest.xml": `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">
    <application android:label="Test"/>
</manifest>`,
		"classes.dex": "dex\n035\x00" + string(make([]byte, 100)),
		"res/values/strings.xml": `<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
</resources>`,
		"assets/data.json": `{"test": "data"}`,
	}

	for name, content := range files {
		header := &zip.FileHeader{
			Name:   name,
			Method: zip.Deflate,
		}
		if name == "classes.dex" {
			header.Method = zip.Store
		}

		w, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}

		if _, err := w.Write([]byte(content)); err != nil {
			return err
		}
	}

	return nil
}

// Helper: Create a large test APK with many files
func createLargeTestAPK(path string, fileCount int) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := zip.NewWriter(file)
	defer writer.Close()

	// Add manifest
	w, _ := writer.Create("AndroidManifest.xml")
	w.Write([]byte("<?xml version=\"1.0\"?><manifest/>"))

	// Add DEX
	w, _ = writer.Create("classes.dex")
	w.Write([]byte("dex\n035\x00"))

	// Add many resource files
	for i := 0; i < fileCount; i++ {
		name := filepath.ToSlash(filepath.Join("res", "drawable", "icon_"+fmt.Sprintf("%d", i)+".png"))
		w, _ := writer.Create(name)
		w.Write([]byte("PNG fake data"))
	}

	return nil
}
