package manifestaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifestFromPlaintextDirectory(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.dir"><uses-sdk android:targetSdkVersion="34"/><application android:allowBackup="false"/></manifest>`)
	if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Package != "com.example.dir" || manifest.TargetSDK != 34 || manifest.Application.AllowBackupDeclared == nil || *manifest.Application.AllowBackupDeclared {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}
