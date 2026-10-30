package apkloader

import (
	"archive/zip"
	"context"
	"io"
	"mega-analyzer/pkg/internal/apkloader/axml"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectMiniSandboxRebuiltFiles(t *testing.T) {
	sourceDir := writeMiniSandbox(t)
	apkPath := filepath.Join(t.TempDir(), "mini-sandbox.apk")
	rebuilder := NewAPKRebuilder(sourceDir)
	rebuilder.UseSmali = false
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = true
	if err := rebuilder.Rebuild(context.Background(), apkPath); err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatalf("Failed to open mini sandbox APK: %v", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") && !strings.HasPrefix(f.Name, "assets/") {
			rc, err := f.Open()
			if err != nil {
				t.Errorf("Failed to open entry %s: %v", f.Name, err)
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Errorf("Failed to read entry %s: %v", f.Name, err)
				continue
			}
			if !axml.IsBinaryXML(data) {
				t.Errorf("NOT binary XML: %s (size %d, first bytes: %q)",
					f.Name, len(data), string(data[:minInt(len(data), 50)]))
			}
		}

		if f.Name == "resources.arsc" {
			rc, err := f.Open()
			if err != nil {
				t.Errorf("Failed to open resources.arsc: %v", err)
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Errorf("Failed to read resources.arsc: %v", err)
				continue
			}
			if _, err := axml.ParseARSC(data); err != nil {
				t.Errorf("resources.arsc failed to parse: %v", err)
			}
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
