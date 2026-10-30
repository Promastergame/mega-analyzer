package apkloader

import (
	"archive/zip"
	"context"
	"io"
	"mega-analyzer/pkg/internal/apkloader/axml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifySandboxRebuild(t *testing.T) {
	sourceDir := writeMiniSandbox(t)

	outApk := filepath.Join(os.TempDir(), "test_sandbox_out.apk")
	defer os.Remove(outApk)

	rebuilder := NewAPKRebuilder(sourceDir)
	rebuilder.UseSmali = false
	rebuilder.IncludeSignature = false
	rebuilder.IncludeAlignment = true

	if err := rebuilder.Rebuild(context.Background(), outApk); err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	zr, err := zip.OpenReader(outApk)
	if err != nil {
		t.Fatalf("Failed to open output zip: %v", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
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

		if strings.HasSuffix(strings.ToLower(f.Name), ".xml") && !strings.HasPrefix(f.Name, "assets/") {
			if !axml.IsBinaryXML(data) {
				lim := 50
				if len(data) < lim {
					lim = len(data)
				}
				t.Errorf("XML file is NOT binary XML in APK: %s (size %d, first bytes: %q)",
					f.Name, len(data), string(data[:lim]))
			} else {
				if f.Name == "AndroidManifest.xml" {
					if _, err := axml.Decode(data); err != nil {
						t.Errorf("AndroidManifest.xml failed to decode: %v", err)
					}
				}
			}
		}

		if f.Name == "resources.arsc" {
			if _, err := axml.ParseARSC(data); err != nil {
				t.Errorf("resources.arsc failed to parse: %v", err)
			}
		}
	}
}
