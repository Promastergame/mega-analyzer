package insights

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPrivacy_E2E_RealAPK verifies the full pipeline:
//  1. extract APK with the loader
//  2. AnalyzePrivacy on the extracted dir
//  3. confirm declared permissions came from the manifest, not from
//     smali heuristics
//
// Skipped when the sample APK is missing.
func TestPrivacy_E2E_RealAPK(t *testing.T) {
	apkPath := `f:\PROJECTS\mega-analyzer\output\base (8).apk`
	if _, err := os.Stat(apkPath); err != nil {
		t.Skipf("sample APK not present: %v", err)
	}
	target := apkPath

	report, err := AnalyzePrivacy(target)
	if err != nil {
		t.Fatalf("AnalyzePrivacy: %v", err)
	}

	manifestCount := 0
	codeCount := 0
	for _, p := range report.Permissions {
		switch p.Origin {
		case "manifest":
			manifestCount++
		case "code":
			codeCount++
		}
	}

	t.Logf("declared (manifest): %d, referenced (code): %d, total perms: %d",
		manifestCount, codeCount, len(report.Permissions))
	t.Logf("trackers: %d, sources: %d, sinks: %d, flows: %d, endpoints: %d",
		len(report.Trackers), len(report.Sources),
		len(report.Sinks), len(report.Flows), len(report.Endpoints))

	if manifestCount == 0 {
		t.Errorf("expected at least one manifest-declared permission")
	}

	// Sample first 5 manifest perms for a smoke check
	shown := 0
	for _, p := range report.Permissions {
		if p.Origin != "manifest" {
			continue
		}
		t.Logf("  declared: %s", p.Name)
		shown++
		if shown >= 5 {
			break
		}
	}
}

func TestPrivacy_PlaintextManifestParser(t *testing.T) {
	dir := t.TempDir()
	manifest := `<?xml version="1.0"?>
<manifest>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
  <uses-permission-sdk-23 android:name="android.permission.CAMERA"/>
</manifest>`
	path := filepath.Join(dir, "AndroidManifest.xml")
	if err := os.WriteFile(path, []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}

	perms := loadManifestPermissions(dir)
	if len(perms) < 2 {
		t.Errorf("expected at least 2 permissions, got %d: %v", len(perms), perms)
	}
}
