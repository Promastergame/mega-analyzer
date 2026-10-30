package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFirstSubmatch(t *testing.T) {
	re := regexp.MustCompile(`name="([^"]+)"`)
	if got := firstSubmatch([]byte(`<x name="alpha"/>`), re); got != "alpha" {
		t.Errorf("firstSubmatch = %q, want alpha", got)
	}
	if got := firstSubmatch([]byte("nothing"), re); got != "" {
		t.Errorf("firstSubmatch on miss = %q, want \"\"", got)
	}
}

const sampleManifest = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application>
        <activity android:name=".MainActivity" android:exported="true"/>
        <service android:name=".BgService"/>
        <receiver android:name=".BootReceiver" android:exported="true"/>
        <provider android:name=".DataProvider" android:exported="false"/>
    </application>
</manifest>`

func TestExtractAndroidPermissions(t *testing.T) {
	got := extractAndroidPermissions([]byte(sampleManifest))
	if len(got) != 2 {
		t.Fatalf("expected 2 unique permissions, got %d (%v)", len(got), got)
	}
	for _, p := range got {
		if p.Name == "" {
			t.Errorf("permission missing name: %+v", p)
		}
	}

	if got := extractAndroidPermissions([]byte("nothing here")); got != nil {
		t.Errorf("empty manifest should yield nil, got %v", got)
	}
}

func TestExtractAndroidComponents(t *testing.T) {
	got := extractAndroidComponents([]byte(sampleManifest))
	if len(got) != 4 {
		t.Fatalf("expected 4 components, got %d", len(got))
	}

	// Components are sorted by kind then name. Check that each kind shows up.
	kinds := map[string]int{}
	for _, c := range got {
		kinds[c.Kind]++
		if c.Name == "" {
			t.Errorf("component missing name: %+v", c)
		}
	}
	for _, want := range []string{"activity", "service", "receiver", "provider"} {
		if kinds[want] == 0 {
			t.Errorf("expected at least one %s component", want)
		}
	}

	// Activity is exported=true.
	for _, c := range got {
		if c.Kind == "activity" && !c.Exported {
			t.Errorf("MainActivity should be Exported=true, got %+v", c)
		}
		if c.Kind == "provider" && c.Exported {
			t.Errorf("DataProvider should be Exported=false, got %+v", c)
		}
	}

	if got := extractAndroidComponents([]byte("no components")); got != nil {
		t.Errorf("missing components should yield nil")
	}
}

func TestFindManifestPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "AndroidManifest.xml")
	if err := os.WriteFile(p, []byte(sampleManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findManifestPath(dir)
	if err != nil {
		t.Fatalf("findManifestPath: %v", err)
	}
	if !strings.Contains(got, "AndroidManifest.xml") {
		t.Errorf("got %q", got)
	}

	// Nested location: root/sub/AndroidManifest.xml — direct lookup fails, so
	// findManifestPath should walk and locate it.
	dir2 := t.TempDir()
	sub := filepath.Join(dir2, "decoded", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "AndroidManifest.xml"), []byte(sampleManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := findManifestPath(dir2); err != nil {
		t.Errorf("walk-based discovery failed: %v", err)
	}

	// Nonexistent root → expect error.
	if _, err := findManifestPath(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("missing root should yield error")
	}
}

func TestCollectAndroidProfileSmoke(t *testing.T) {
	// collectAndroidProfile relies on apkloader.DetectInputType which expects
	// a real APK or directory layout; we exercise the smaller helpers above
	// instead. Keep this as a stub so the file compiles cleanly.
	_ = sampleManifest
}
