package apkloader

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestArchivePreservesPrimaryAPKFilesWithResourceDirectories(t *testing.T) {
	entries := map[string]string{
		"AndroidManifest.xml":                     "manifest",
		"classes.dex":                             "dex",
		"resources.arsc":                          "resource table",
		"AndroidManifest.xml/anim/one.xml":        "manifest-prefixed resource",
		"classes.dex/anim/two.xml":                "dex-prefixed resource",
		"resources.arsc/anim/three.xml":           "table-prefixed resource",
		"AndroidManifest.xml_resources1/keep.txt": "original directory",
	}
	dest := testutil.TempDir(t)
	if _, err := runSecurityZIP(t, securityZIP(t, entries), dest); err != nil {
		t.Fatalf("file/directory collisions must not abort extraction: %v", err)
	}
	want := map[string]string{
		"AndroidManifest.xml": "manifest",
		"classes.dex":         "dex",
		"resources.arsc":      "resource table",
		"AndroidManifest.xml_resources2/anim/one.xml": "manifest-prefixed resource",
		"classes.dex_resources1/anim/two.xml":         "dex-prefixed resource",
		"resources.arsc_resources1/anim/three.xml":    "table-prefixed resource",
		"AndroidManifest.xml_resources1/keep.txt":     "original directory",
	}
	for rel, content := range want {
		data, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil || string(data) != content {
			t.Errorf("archive member %q was lost or changed: %q, %v", rel, data, err)
		}
	}
}

func TestArchiveDisambiguatesGenericFileDirectoryCollision(t *testing.T) {
	dest := testutil.TempDir(t)
	if _, err := runSecurityZIP(t, securityZIP(t, map[string]string{"a": "file", "a/b": "child"}), dest); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{"a_dup1": "file", "a/b": "child"} {
		data, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil || string(data) != want {
			t.Errorf("collision member %q was not preserved: %q, %v", rel, data, err)
		}
	}
}
