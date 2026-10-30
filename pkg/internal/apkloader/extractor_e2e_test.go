package apkloader

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

// TestExtractor_DecodeHelpers_BeatStar exercises the AXML/ARSC
// decoding helpers directly, without running the multi-DEX pipeline.
//
// We don't run the full PrepareInput here because it kicks off DEX
// decompilation that takes minutes on the bundled BeatStar APK; that
// path is exercised separately by integration tests. This test only
// validates the new resource-decoding hooks added by the AXML/ARSC
// integration.
func TestExtractor_DecodeHelpers_BeatStar(t *testing.T) {
	apkPath := `f:\PROJECTS\mega-analyzer\output\base (8).apk`
	if _, err := os.Stat(apkPath); err != nil {
		t.Skipf("sample APK not present: %v", err)
	}

	dir := t.TempDir()
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatalf("open apk: %v", err)
	}
	defer zr.Close()

	// Extract just AndroidManifest.xml + resources.arsc + a few res/*.xml
	// — enough to exercise the decode helpers without touching DEX.
	resTested := 0
	for _, f := range zr.File {
		base := strings.ToLower(filepath.Base(f.Name))
		isManifest := base == "androidmanifest.xml"
		isARSC := base == "resources.arsc"
		isResXML := isResourceXMLPath(f.Name) && resTested < 5
		if !(isManifest || isARSC || isResXML) {
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(dst)
		if err != nil {
			rc.Close()
			continue
		}
		_, _ = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if isResXML {
			resTested++
		}
	}

	manifestPath := filepath.Join(dir, "AndroidManifest.xml")
	arscPath := filepath.Join(dir, "resources.arsc")

	// 1. Decode manifest
	m, err := decodeAndSaveManifest(manifestPath)
	if err != nil {
		t.Fatalf("decodeAndSaveManifest: %v", err)
	}
	if m == nil || m.Package != "ai.character.app" {
		t.Errorf("manifest package = %q, want ai.character.app", m.Package)
	}
	if data, err := os.ReadFile(manifestPath); err != nil {
		t.Errorf("read decoded manifest: %v", err)
	} else if !strings.HasPrefix(strings.TrimSpace(string(data)), "<?xml") {
		t.Errorf("manifest not rewritten as plaintext")
	}
	if _, err := os.Stat(manifestPath + ".bin"); err != nil {
		t.Errorf("manifest .bin sibling missing")
	}

	// 2. Decode ARSC
	if err := decodeAndSaveARSC(arscPath); err != nil {
		t.Fatalf("decodeAndSaveARSC: %v", err)
	}
	if info, err := os.Stat(arscPath + ".json"); err != nil {
		t.Errorf("arsc.json missing: %v", err)
	} else if info.Size() < 1024 {
		t.Errorf("arsc.json too small: %d", info.Size())
	}

	// 3. Decode res XMLs
	resXMLDecoded := 0
	_ = filepath.WalkDir(filepath.Join(dir, "res"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".xml") {
			return nil
		}
		if err := decodeAndSaveAXML(p); err != nil {
			t.Logf("decode %s: %v", p, err)
			return nil
		}
		// Verify it's no longer binary.
		data, _ := os.ReadFile(p)
		if !axml.IsBinaryXML(data) {
			resXMLDecoded++
		}
		return nil
	})
	if resXMLDecoded == 0 {
		t.Errorf("no res XMLs decoded successfully")
	}
	t.Logf("decoded %d res XMLs in tree", resXMLDecoded)
}
