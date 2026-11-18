package apkloader

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/apkloader/axml"

	"mega-analyzer/pkg/internal/testutil"
)

func TestNativeProjectRebuildNoExternalTools(t *testing.T) {
	t.Setenv("MEGA_STANDALONE", "1")
	source := testutil.TempDir(t)
	files := map[string]string{
		"AndroidManifest.xml":      `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.native" android:versionCode="1"><uses-sdk android:minSdkVersion="21"/><application android:label="@string/app_name"/></manifest>`,
		"res/values/strings.xml":   `<resources><string name="app_name">Standalone build</string></resources>`,
		"res/raw/config.xml":       `<config>not binary XML</config>`,
		"assets/data.txt":          "asset content",
		"smali/example/Main.smali": ".class public Lexample/Main;\n.super Ljava/lang/Object;\n",
	}
	for path, content := range files {
		full := filepath.Join(source, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(testutil.TempDir(t), "native.apk")
	r := NewAPKRebuilder(source)
	if err := r.Rebuild(context.Background(), output); err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	entries := map[string][]byte{}
	for _, f := range z.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		entries[f.Name] = data
		if strings.HasPrefix(f.Name, "build/") || strings.HasSuffix(f.Name, ".smali") || strings.HasPrefix(f.Name, "res/values/") {
			t.Fatalf("build input shipped: %s", f.Name)
		}
	}
	if !axml.IsBinaryXML(entries["AndroidManifest.xml"]) {
		t.Fatal("manifest was not compiled")
	}
	table, err := axml.ParseARSC(entries["resources.arsc"])
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Packages) != 1 || table.Packages[0].Name != "example.native" {
		t.Fatalf("resource table: %+v", table)
	}
	if !bytes.HasPrefix(entries["classes.dex"], []byte("dex\n")) {
		t.Fatal("DEX not assembled")
	}
	if string(entries["res/raw/config.xml"]) != files["res/raw/config.xml"] {
		t.Fatal("raw XML changed")
	}
	if _, err := VerifyV1SignatureOffline(output); err != nil {
		t.Fatal(err)
	}
	if v, err := VerifyV2V3Offline(output); err != nil || !v.V2 || !v.V3 {
		t.Fatalf("APK signatures: %+v %v", v, err)
	}
	if err := VerifyAlignment(output); err != nil {
		t.Fatal(err)
	}
}

func TestRebuildFailurePreservesExistingAPK(t *testing.T) {
	t.Setenv("MEGA_STANDALONE", "1")
	for _, mode := range []string{"fresh", "overlay"} {
		t.Run(mode, func(t *testing.T) {
			source := testutil.TempDir(t)
			manifest := filepath.Join(source, "AndroidManifest.xml")
			if err := os.WriteFile(manifest, []byte(`<manifest package="example.app"><application>`), 0644); err != nil {
				t.Fatal(err)
			}
			if mode == "overlay" {
				if err := os.WriteFile(manifest+".bin", axml.MinimalManifestXML(), 0644); err != nil {
					t.Fatal(err)
				}
				future := time.Now().Add(time.Second)
				if err := os.Chtimes(manifest, future, future); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(testutil.TempDir(t), "existing.apk")
			original := []byte("previous successful artifact")
			if err := os.WriteFile(output, original, 0644); err != nil {
				t.Fatal(err)
			}
			r := NewAPKRebuilder(source)
			r.IncludeSignature = false
			r.IncludeAlignment = false
			if err := r.Rebuild(context.Background(), output); err == nil {
				t.Fatal("malformed XML build unexpectedly succeeded")
			}
			got, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("previous output lost: %q %v", got, err)
			}
			files, err := filepath.Glob(filepath.Join(filepath.Dir(output), ".mega-analyzer-build-*"))
			if err != nil || len(files) != 0 {
				t.Fatalf("staged files leaked: %v %v", files, err)
			}
		})
	}
}

func TestOverlayOlderTextStillAppliesEdits(t *testing.T) {
	for _, tc := range []struct{ path, oldText, newText, attr, want string }{
		{"AndroidManifest.xml", `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app"><application android:label="Original"/></manifest>`, `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app"><application android:label="Edited"/></manifest>`, "label", "Edited"},
		{"res/layout/main.xml", `<TextView xmlns:android="http://schemas.android.com/apk/res/android" android:text="Original"/>`, `<TextView xmlns:android="http://schemas.android.com/apk/res/android" android:text="Edited"/>`, "text", "Edited"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			source := testutil.TempDir(t)
			path := filepath.Join(source, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			bin, err := axml.CompileTextAXML([]byte(tc.oldText), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".bin", bin, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.newText), 0644); err != nil {
				t.Fatal(err)
			}
			older := time.Now().Add(-24 * time.Hour)
			if err := os.Chtimes(path, older, older); err != nil {
				t.Fatal(err)
			}
			r := NewAPKRebuilder(source)
			if err := r.overlayTextXML(tc.path, nil); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path + ".bin")
			if err != nil {
				t.Fatal(err)
			}
			doc, err := axml.ParseBinaryAXML(data)
			if err != nil {
				t.Fatal(err)
			}
			element := doc.Root
			if len(element.Kids) > 0 {
				element = element.Kids[0]
			}
			found := false
			for _, a := range element.Attrs {
				if a.Name == tc.attr {
					found = true
					if a.Str != tc.want {
						t.Fatalf("older edited text was ignored: %+v", a)
					}
				}
			}
			if !found {
				t.Fatalf("missing edited attribute %s", tc.attr)
			}
		})
	}
}

func TestRebuildBinaryResourcesWithoutExportMarker(t *testing.T) {
	t.Setenv("MEGA_STANDALONE", "1")
	project := testutil.TempDir(t)
	if err := os.MkdirAll(filepath.Join(project, "res", "values"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "AndroidManifest.xml"), []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.raw"><application android:label="@string/title"/></manifest>`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "res", "values", "strings.xml"), []byte(`<resources><string name="title">Undecoded</string></resources>`), 0644); err != nil {
		t.Fatal(err)
	}
	compiled, err := axml.CompileResourceDirectory(context.Background(), project)
	if err != nil {
		t.Fatal(err)
	}
	// A --no-resources decode has only binary resources, with no export marker.
	source := testutil.TempDir(t)
	for path, data := range compiled.Binary {
		if err := os.WriteFile(filepath.Join(source, path), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	r := NewAPKRebuilder(source)
	r.IncludeSignature = false
	r.IncludeAlignment = false
	output := filepath.Join(testutil.TempDir(t), "binary.apk")
	if err := r.Rebuild(context.Background(), output); err != nil {
		t.Fatalf("no-resources rebuild required XML exports: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "resources.arsc.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := r.Rebuild(context.Background(), output); err == nil {
		t.Fatal("missing exported resources accepted despite native export marker")
	}
}
