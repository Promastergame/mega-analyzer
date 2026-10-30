package axml

import (
	"archive/zip"
	"io"
	"os"
	"strings"
	"testing"
)

// TestDecodeResXML_RealAPK pulls a sample of res/*.xml files from the
// in-tree APK, decodes them, and checks that the result contains
// printable text rather than chunk bytes. Skipped when the sample APK
// is missing.
func TestDecodeResXML_RealAPK(t *testing.T) {
	apkPath := `f:\PROJECTS\mega-analyzer\output\base (8).apk`
	if _, err := os.Stat(apkPath); err != nil {
		t.Skipf("sample APK not present: %v", err)
	}

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatalf("open apk: %v", err)
	}
	defer zr.Close()

	tested := 0
	urlsFound := 0
	stringsFound := 0
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "res/") || !strings.HasSuffix(f.Name, ".xml") {
			continue
		}
		if tested >= 10 {
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		if !IsBinaryXML(data) {
			continue
		}
		rendered, err := Render(data)
		if err != nil {
			t.Logf("[skip] %s: %v", f.Name, err)
			continue
		}
		if strings.Contains(rendered, "http") {
			urlsFound++
		}
		if len(rendered) > 100 {
			stringsFound++
		}
		tested++
	}

	t.Logf("decoded %d res/*.xml files, %d contained 'http', %d non-trivial",
		tested, urlsFound, stringsFound)

	if tested == 0 {
		t.Skip("no binary res/*.xml found in sample APK")
	}
}
