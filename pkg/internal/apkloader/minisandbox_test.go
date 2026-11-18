package apkloader

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/testutil"
)

const miniSandboxSmali = `.class public Lcom/example/Mini;
.super Ljava/lang/Object;

.method public static value()I
    .registers 1
    const/4 v0, 0x0
    return v0
.end method
`

// writeMiniSandbox creates a small, deterministic decoded-APK tree.
//
// The tree is intentionally independent of the host: it contains a binary
// manifest, a binary resource XML, a minimal ARSC table, one smali class, a
// DEX placeholder, one asset, and one native library. Rebuild tests use it as
// their own mini sandbox instead of reading user files from Downloads.
func writeMiniSandbox(t *testing.T) string {
	t.Helper()

	root := testutil.TempDir(t)
	directories := []string{
		"res/values",
		"smali/com/example",
		"assets",
		"lib/arm64-v8a",
	}
	for _, directory := range directories {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0755); err != nil {
			t.Fatalf("create mini sandbox directory: %v", err)
		}
	}

	files := map[string][]byte{
		"AndroidManifest.xml":          axml.MinimalManifestXML(),
		"res/values/strings.xml":       axml.MinimalManifestXML(),
		"resources.arsc":               axml.MinimalARSC(),
		"classes.dex":                  []byte("dex\n035\x00"),
		"assets/data.txt":              []byte("mini sandbox\n"),
		"lib/arm64-v8a/libmini.so":     []byte("mini native library\n"),
		"smali/com/example/Mini.smali": []byte(miniSandboxSmali),
	}
	for name, data := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write mini sandbox file %s: %v", name, err)
		}
	}
	return root
}
