package apkloader

import (
	"archive/zip"
	"context"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitMerger_Merge(t *testing.T) {
	// 1. Setup temporary workspace
	tempDir, err := os.MkdirTemp("", "merger_test_workspace_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Directories for split sources and merged output
	srcDir := filepath.Join(tempDir, "splits")
	destDir := filepath.Join(tempDir, "merged")
	os.MkdirAll(srcDir, 0755)
	os.MkdirAll(destDir, 0755)

	// 2. Create mock Base APK zip file
	baseAPKPath := filepath.Join(srcDir, "base.apk")
	createMockAPK(t, baseAPKPath, map[string]string{
		"AndroidManifest.xml": `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:name="com.test.app.MainApp">
        <activity android:name="com.test.app.MainActivity" android:exported="true" />
    </application>
</manifest>`,
		"classes.dex":                 "baseDEXContent",
		"lib/arm64-v8a/libbasejni.so": "baseJNILib",
	})

	// 3. Create mock Split APK 1 (Config/Feature APK with permissions and DEX)
	splitAPK1Path := filepath.Join(srcDir, "split_feature.apk")
	createMockAPK(t, splitAPK1Path, map[string]string{
		"AndroidManifest.xml": `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app" split="feature">
    <uses-permission android:name="android.permission.CAMERA" />
    <application>
        <activity android:name="com.test.app.FeatureActivity" />
    </application>
</manifest>`,
		"classes.dex": "featureDEXContent",
	})

	// 4. Create mock Split APK 2 (Native library split)
	splitAPK2Path := filepath.Join(srcDir, "split_config.arm64_v8a.apk")
	createMockAPK(t, splitAPK2Path, map[string]string{
		"lib/arm64-v8a/libsplitjni.so": "splitJNILib",
		"assets/feature_config.json":   `{"enabled":true}`,
	})

	// 5. Run the Split APK Merger
	extractor := NewExtractor()
	merger := NewSplitMerger(tempDir)
	apkFiles := []string{baseAPKPath, splitAPK1Path, splitAPK2Path}

	err = merger.Merge(context.Background(), extractor, apkFiles, destDir)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// 6. Verify merged AndroidManifest.xml
	mergedManifestPath := filepath.Join(destDir, "AndroidManifest.xml")
	manifestData, err := os.ReadFile(mergedManifestPath)
	if err != nil {
		t.Fatalf("failed to read merged manifest: %v", err)
	}
	manifestStr := string(manifestData)

	// Check permissions merged
	if !strings.Contains(manifestStr, "android.permission.INTERNET") {
		t.Error("missing INTERNET permission from base manifest")
	}
	if !strings.Contains(manifestStr, "android.permission.CAMERA") {
		t.Error("missing CAMERA permission from split manifest")
	}

	// Check components merged under <application>
	if !strings.Contains(manifestStr, "com.test.app.MainActivity") {
		t.Error("missing MainActivity from base app")
	}
	if !strings.Contains(manifestStr, "com.test.app.FeatureActivity") {
		t.Error("missing FeatureActivity from split app")
	}

	// Verify the XML is valid XML structure
	var parsed SplitManifest
	if err := xml.Unmarshal(manifestData, &parsed); err != nil {
		t.Errorf("merged manifest is not valid XML: %v", err)
	}

	// 7. Verify merged DEX files
	// base has classes.dex, split_feature has classes.dex (should be classes2.dex)
	classesPath := filepath.Join(destDir, "classes.dex")
	classes2Path := filepath.Join(destDir, "classes2.dex")

	if data, err := os.ReadFile(classesPath); err != nil || string(data) != "baseDEXContent" {
		t.Errorf("classes.dex incorrect: err=%v data=%s", err, string(data))
	}
	if data, err := os.ReadFile(classes2Path); err != nil || string(data) != "featureDEXContent" {
		t.Errorf("classes2.dex incorrect: err=%v data=%s", err, string(data))
	}

	// 8. Verify native libraries merged
	lib1Path := filepath.Join(destDir, "lib", "arm64-v8a", "libbasejni.so")
	lib2Path := filepath.Join(destDir, "lib", "arm64-v8a", "libsplitjni.so")

	if data, err := os.ReadFile(lib1Path); err != nil || string(data) != "baseJNILib" {
		t.Errorf("libbasejni.so incorrect: err=%v", err)
	}
	if data, err := os.ReadFile(lib2Path); err != nil || string(data) != "splitJNILib" {
		t.Errorf("libsplitjni.so incorrect: err=%v", err)
	}

	// 9. Verify assets merged
	assetPath := filepath.Join(destDir, "assets", "feature_config.json")
	if data, err := os.ReadFile(assetPath); err != nil || !strings.Contains(string(data), "enabled") {
		t.Errorf("feature_config.json incorrect: err=%v", err)
	}
}

func createMockAPK(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatal(err)
		}
	}
}
