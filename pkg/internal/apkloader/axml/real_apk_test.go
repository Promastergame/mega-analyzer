package axml

import (
	"archive/zip"
	"io"
	"os"
	"strings"
	"testing"
)

// TestDecode_RealAPK_BeatStar parses AndroidManifest.xml from the
// in-tree sample APK if it's available. Skipped on machines that
// don't have the artifact (CI runners, fresh clones).
func TestDecode_RealAPK_BeatStar(t *testing.T) {
	apkPath := `f:\PROJECTS\mega-analyzer\output\base (8).apk`
	if _, err := os.Stat(apkPath); err != nil {
		t.Skipf("sample APK not present: %v", err)
	}

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatalf("open apk: %v", err)
	}
	defer zr.Close()

	var manifestBytes []byte
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, "AndroidManifest.xml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open manifest entry: %v", err)
		}
		manifestBytes, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read manifest entry: %v", err)
		}
		break
	}
	if len(manifestBytes) == 0 {
		t.Skip("no AndroidManifest.xml inside the sample APK")
	}

	if !IsBinaryXML(manifestBytes) {
		t.Fatalf("manifest is not binary XML (first bytes: % x)", manifestBytes[:8])
	}

	m, err := Decode(manifestBytes)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if m.Package == "" {
		t.Errorf("expected non-empty package, got empty")
	}
	if len(m.Permissions) == 0 {
		t.Errorf("expected at least one permission")
	}
	t.Logf("Decoded BeatStar manifest:\n%s", m.Summary())
	t.Logf("First 5 permissions: %v", firstN(m.Permissions, 5))
	t.Logf("Activities: %d, Services: %d, Receivers: %d, Providers: %d",
		len(m.Activities), len(m.Services), len(m.Receivers), len(m.Providers))
	t.Logf("Rendered XML preview (first 800 chars):\n%s", previewString(string(m.XMLBytes), 800))
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func previewString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
