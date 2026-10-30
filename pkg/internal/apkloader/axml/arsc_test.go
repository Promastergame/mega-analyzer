package axml

import (
	"archive/zip"
	"io"
	"os"
	"strings"
	"testing"
)

// TestParseARSC_RealAPK_BeatStar exercises the ARSC decoder on the
// in-tree sample APK if it's available.
func TestParseARSC_RealAPK_BeatStar(t *testing.T) {
	apkPath := `f:\PROJECTS\mega-analyzer\output\base (8).apk`
	if _, err := os.Stat(apkPath); err != nil {
		t.Skipf("sample APK not present: %v", err)
	}

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatalf("open apk: %v", err)
	}
	defer zr.Close()

	var arscBytes []byte
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, "resources.arsc") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open arsc: %v", err)
		}
		arscBytes, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read arsc: %v", err)
		}
		break
	}
	if len(arscBytes) == 0 {
		t.Skip("no resources.arsc inside the sample APK")
	}

	t.Logf("ARSC size: %d bytes", len(arscBytes))

	table, err := ParseARSC(arscBytes)
	if err != nil {
		t.Fatalf("ParseARSC: %v", err)
	}
	if len(table.Packages) == 0 {
		t.Fatal("expected at least one package")
	}

	for i, p := range table.Packages {
		t.Logf("package[%d]: id=0x%02x name=%q types=%d libraries=%d",
			i, p.ID, p.Name, len(p.Types), len(p.Libraries))
		shown := 0
		for _, typ := range p.Types {
			if typ.Name != "string" {
				continue
			}
			for _, e := range typ.Entries {
				if shown >= 5 {
					break
				}
				if len(e.Values) == 0 {
					continue
				}
				t.Logf("  string/%s = %q (%d configs)", e.Name, e.Values[0].Value, len(e.Values))
				shown++
			}
			break
		}
	}
}
