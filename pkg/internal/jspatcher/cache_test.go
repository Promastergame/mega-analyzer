package jspatcher

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchFilePersistentCacheAndSourceMapInvalidation(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	mapPath := bundle + ".map"
	if err := os.WriteFile(bundle, []byte("var generated=1;\n//# sourceMappingURL=bundle.js.map\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapPath, []byte(`{"version":3,"sources":["a.js"],"sourcesContent":["const isPremium=false;"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.MinConfidence = 0
	cfg.OutputDir = filepath.Join(dir, "reports", "jspatcher")
	patcher := NewPatcher(cfg)
	first, err := patcher.PatchFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if first.CacheHit {
		t.Fatal("first scan must not be a cache hit")
	}
	second, err := patcher.PatchFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !second.CacheHit {
		t.Fatal("second identical dry-run should use persistent cache")
	}
	if err := os.WriteFile(mapPath, []byte(`{"version":3,"sources":["a.js"],"sourcesContent":["const adsEnabled=true;"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := patcher.PatchFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if changed.CacheHit {
		t.Fatal("source-map content change must invalidate cache")
	}
}

func TestHermesPatchReportUsesBuiltInParser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.android.bundle")
	data := make([]byte, 128)
	copy(data, []byte{0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f})
	binary.LittleEndian.PutUint32(data[8:12], 96)
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(data)))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.OutputDir = filepath.Join(dir, "reports", "jspatcher")
	result, err := NewPatcher(cfg).PatchFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsHermes || len(result.Hermes) != 1 || !result.Hermes[0].Parsed || result.Hermes[0].Version != 96 {
		t.Fatalf("unexpected Hermes analysis: %#v", result.Hermes)
	}
	var report strings.Builder
	writeMD(&report, result)
	text := report.String()
	if !strings.Contains(text, "built-in HBC parser") {
		t.Fatalf("report does not describe built-in parser: %s", text)
	}
	if strings.Contains(text, "hermes-dec") || strings.Contains(text, "hbctool") {
		t.Fatal("report must not require external Hermes tools")
	}
}
