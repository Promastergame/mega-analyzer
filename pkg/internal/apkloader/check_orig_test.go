package apkloader

import (
	"archive/zip"
	"context"
	"io"
	"mega-analyzer/pkg/internal/apkloader/axml"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestMiniSandboxOriginalEntries(t *testing.T) {
	sourceDir := writeMiniSandbox(t)
	origXapk := filepath.Join(testutil.TempDir(t), "mini-sandbox.apk")
	rebuilder := NewAPKRebuilder(sourceDir)
	rebuilder.UseSmali = false
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = true
	if err := rebuilder.Rebuild(context.Background(), origXapk); err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	zr, err := zip.OpenReader(origXapk)
	if err != nil {
		t.Fatalf("Failed to open original: %v", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") && !strings.HasPrefix(f.Name, "assets/") {
			t.Logf("Checking XML entry: %s", f.Name)
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			t.Logf("Original %s: size=%d, isBinary=%v", f.Name, len(data), axml.IsBinaryXML(data))
			if !axml.IsBinaryXML(data) {
				t.Errorf("Entry %s is not binary XML", f.Name)
			}
		}
	}
}
