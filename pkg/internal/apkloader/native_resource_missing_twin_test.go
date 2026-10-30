package apkloader

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

func TestNativeExistingResourcesCompileMissingXMLTwins(t *testing.T) {
	source := t.TempDir()
	files := map[string]string{
		"AndroidManifest.xml":    `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.twin"><application android:label="@string/title"/></manifest>`,
		"res/values/strings.xml": `<resources><string name="title">Title</string></resources>`,
		"res/layout/main.xml":    `<TextView xmlns:android="http://schemas.android.com/apk/res/android" android:layout_width="match_parent" android:layout_height="wrap_content" android:text="@string/title"/>`,
		"res/raw/config.xml":     `<plain>leave raw</plain>`,
	}
	for rel, data := range files {
		path := filepath.Join(source, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	compiled, err := axml.CompileResourceDirectory(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "resources.arsc"), compiled.Binary["resources.arsc"], 0644); err != nil {
		t.Fatal(err)
	}
	r := NewAPKRebuilder(source)
	if err := r.syncAndPatchResources(); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"AndroidManifest.xml", "res/layout/main.xml"} {
		data, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(rel+".bin")))
		if err != nil || !axml.IsBinaryXML(data) {
			t.Fatalf("missing compiled %s: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(source, "res/raw/config.xml.bin")); !os.IsNotExist(err) {
		t.Fatalf("raw XML was compiled: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "res/layout/new.xml"), []byte(files["res/layout/main.xml"]), 0644); err != nil {
		t.Fatal(err)
	}
	if err := r.syncAndPatchResources(); err == nil || !strings.Contains(err.Error(), "adding resource files") {
		t.Fatalf("unregistered layout must fail: %v", err)
	}
}
