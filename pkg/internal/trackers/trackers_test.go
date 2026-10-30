package trackers

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDB_NotEmpty(t *testing.T) {
	db, err := LoadDB()
	if err != nil {
		t.Fatalf("load db: %v", err)
	}
	if len(db) < 100 {
		t.Fatalf("expected at least 100 trackers in DB, got %d", len(db))
	}
	// Must contain some well-known names.
	names := map[string]bool{}
	for _, t := range db {
		names[t.Name] = true
	}
	for _, want := range []string{"Google Firebase Analytics", "Google AdMob", "AppsFlyer"} {
		if !names[want] {
			t.Errorf("expected DB to contain tracker %q", want)
		}
	}
}

func writeArchive(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	apk := filepath.Join(dir, "fake.apk")
	f, err := os.Create(apk)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, payload := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	zw.Close()
	f.Close()
	return apk
}

func TestScan_DetectsCommonTrackers(t *testing.T) {
	apk := writeArchive(t, map[string][]byte{
		"smali/com/google/android/gms/analytics/Tracker.smali": []byte(
			"# uses com/google/android/gms/analytics package\nconst-string v0, \"x\""),
		"smali/com/google/firebase/analytics/FirebaseAnalytics.smali": []byte(
			"# class com/google/firebase/analytics/FirebaseAnalytics"),
		"res/values/strings.xml": []byte(
			`<resources><string name="x">https://api.appsflyer.com/track</string></resources>`),
	})
	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Total < 2 {
		t.Fatalf("expected at least 2 tracker matches, got %d (%v)", rep.Total, rep.Matches)
	}
	names := []string{}
	for _, m := range rep.Matches {
		names = append(names, m.Name)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"Firebase", "AppsFlyer"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected match containing %q, got %v", want, names)
		}
	}
	if rep.Verdict != "moderate" && rep.Verdict != "minimal" && rep.Verdict != "heavy" {
		t.Errorf("verdict expected minimal/moderate/heavy, got %q", rep.Verdict)
	}
}

func TestScan_NoTrackers(t *testing.T) {
	apk := writeArchive(t, map[string][]byte{
		"AndroidManifest.xml": []byte(`<manifest package="com.example.app"/>`),
		"res/values/x.xml":    []byte(`<resources><string name="t">hello</string></resources>`),
	})
	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Total != 0 || rep.Verdict != "clean" {
		t.Fatalf("expected clean report, got %+v", rep)
	}
}

func TestScan_DirectoryMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "smali", "com", "google", "android", "gms", "ads"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "smali", "com", "google", "android", "gms", "ads", "AdView.smali"),
		[]byte("class com/google/android/gms/ads/AdView"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rep, err := Scan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Total == 0 {
		t.Fatalf("expected at least one match in dir mode, got none")
	}
}
