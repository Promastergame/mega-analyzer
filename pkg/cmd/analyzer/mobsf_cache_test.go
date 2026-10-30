package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMobSFCacheRoundTripAndContentInvalidation(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(apk, []byte("apk-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := newMobSFCache(out, apk, "")
	if cache == nil {
		t.Fatal("expected APK-backed cache")
	}
	type cachedReport struct {
		Count int `json:"count"`
	}
	if err := cache.save("test", cachedReport{Count: 7}); err != nil {
		t.Fatal(err)
	}
	var loaded cachedReport
	if !cache.load("test", &loaded) || loaded.Count != 7 {
		t.Fatalf("cache round trip failed: %+v", loaded)
	}
	if err := os.WriteFile(apk, []byte("apk-v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := newMobSFCache(out, apk, "")
	if changed == nil || changed.dir == cache.dir {
		t.Fatal("APK content change must invalidate the result cache key")
	}
	if changed.load("test", &loaded) {
		t.Fatal("changed APK must not reuse the old report")
	}
}

func TestCleanOutputPreservesPersistentCache(t *testing.T) {
	out := filepath.Join(t.TempDir(), "custom-output")
	if err := os.MkdirAll(filepath.Join(out, ".cache", "mobsf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputMarker(out); err != nil {
		t.Fatal(err)
	}
	cacheFile := filepath.Join(out, ".cache", "mobsf", "entry.json")
	if err := os.WriteFile(cacheFile, []byte("cached"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(out, "stale.json")
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanOutputDir(out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("cache should survive cleanup: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale output should be removed, err=%v", err)
	}
}
