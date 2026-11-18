package apkloader

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestDecodeCacheHitMissAndOptionInvalidation(t *testing.T) {
	dir := testutil.TempDir(t)
	apk := filepath.Join(dir, "app.apk")
	out := filepath.Join(dir, "decoded")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apk, []byte("apk-one"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := DecodeOptions{NoResources: true, NoSmali: true}
	meta, err := buildDecodeCacheMetadata(apk, opts)
	if err != nil {
		t.Fatal(err)
	}
	if decodeCacheHit(out, meta, opts) {
		t.Fatal("cache must miss before metadata is written")
	}
	if err := writeDecodeCacheMetadata(out, meta); err != nil {
		t.Fatal(err)
	}
	if !decodeCacheHit(out, meta, opts) {
		t.Fatal("expected cache hit")
	}
	changedOpts := opts
	changedOpts.CopyOriginal = true
	changedMeta, err := buildDecodeCacheMetadata(apk, changedOpts)
	if err != nil {
		t.Fatal(err)
	}
	if decodeCacheHit(out, changedMeta, changedOpts) {
		t.Fatal("decode option change must invalidate cache")
	}
	if err := os.WriteFile(apk, []byte("apk-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	changedAPK, err := buildDecodeCacheMetadata(apk, opts)
	if err != nil {
		t.Fatal(err)
	}
	if decodeCacheHit(out, changedAPK, opts) {
		t.Fatal("APK content change must invalidate cache")
	}
	// Replacing an existing marker must work on Windows too.
	if err := writeDecodeCacheMetadata(out, changedAPK); err != nil {
		t.Fatalf("replace cache marker: %v", err)
	}
}

func TestPrepareInputKeepsDEXAndNeverWritesSmali(t *testing.T) {
	dir := testutil.TempDir(t)
	apkPath := filepath.Join(dir, "app.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	dexEntry, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dexEntry.Write(makeMinimalDEX()); err != nil {
		t.Fatal(err)
	}
	manifest, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Write([]byte(`<manifest package="com.example"/>`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	extractor := NewExtractor()
	extractor.TempDir = dir
	out, err := extractor.PrepareInput(t.Context(), apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer extractor.Cleanup(out)
	if _, err := os.Stat(filepath.Join(out, "classes.dex")); err != nil {
		t.Fatalf("classes.dex not preserved: %v", err)
	}
	err = filepath.WalkDir(out, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".smali" {
			t.Fatalf("analysis generated forbidden Smali file: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
