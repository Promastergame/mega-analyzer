package jspatcher

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestPatchFileExternalSourceMapIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.js")
	mapPath := bundlePath + ".map"
	if err := os.WriteFile(bundlePath, []byte("console.log('generated');\n//# sourceMappingURL=bundle.js.map\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mapJSON := `{"version":3,"sources":["src/paywall.js"],"sourcesContent":["function isPremium() { return false; }"]}`
	if err := os.WriteFile(mapPath, []byte(mapJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.MinConfidence = 0
	result, err := NewPatcher(cfg).PatchFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected a finding recovered from sourcesContent")
	}
	for _, match := range result.Matches {
		if !match.FromSourceMap {
			continue
		}
		if match.SourceMapPath != mapPath {
			t.Fatalf("SourceMapPath = %q, want %q", match.SourceMapPath, mapPath)
		}
		if match.ProposedPatch != nil || result.PatchCount != 0 {
			t.Fatal("source-map-only finding must not propose a bundle patch")
		}
		return
	}
	t.Fatal("expected FromSourceMap finding")
}

func TestPatchFileInlineBase64SourceMap(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "index.android.bundle")
	mapJSON := `{"version":3,"sources":["webpack:///src/subscription.js"],"sourcesContent":["const isPremium = false;"]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(mapJSON))
	bundle := "var generated=1;\n//# sourceMappingURL=data:application/json;charset=utf-8;base64," + encoded + "\n"
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.MinConfidence = 0
	result, err := NewPatcher(cfg).PatchFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range result.Matches {
		if match.FromSourceMap {
			found = true
			if match.SourceMapPath != bundlePath+"#inline-source-map" {
				t.Fatalf("unexpected inline map path %q", match.SourceMapPath)
			}
		}
	}
	if !found {
		t.Fatal("expected finding from inline base64 source map")
	}
	if result.PatchCount != 0 {
		t.Fatalf("PatchCount = %d, want 0 for source-map-only findings", result.PatchCount)
	}
}

func TestCodeRegionsDoesNotTreatURLAsComment(t *testing.T) {
	src := `const endpoint = "https://api.example.com/v1"; // actual comment`
	regions := codeRegions(src)
	var code string
	for _, region := range regions {
		code += src[region.start:region.end]
	}
	if code != `const endpoint = "https://api.example.com/v1"; ` {
		t.Fatalf("code regions corrupted URL string: %q", code)
	}
}

func TestSourceMapReferenceCannotEscapeBundleDirectory(t *testing.T) {
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.map")
	if err := os.WriteFile(outside, []byte(`{"version":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSourceMapReference(filepath.Join(bundleDir, "app.js"), "../outside.map"); err == nil {
		t.Fatal("source-map traversal should be rejected")
	}
}
