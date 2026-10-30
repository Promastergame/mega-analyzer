package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/apkloader"
)

func staticTestApp(opts *CLIOptions) *App {
	return &App{opts: opts, output: NewOutputWithWriter(NoColorTheme(), false, &bytes.Buffer{})}
}
func TestStaticBundleOutputsPersistAndDoNotPatchOriginal(t *testing.T) {
	input := filepath.Join(t.TempDir(), "test.js")
	data := []byte(`const endpoint = "https://api.example.com"; function test(){ return true; }`)
	os.WriteFile(input, data, 0600)
	app := staticTestApp(&CLIOptions{Target: input, BundleExport: true, BundlePatches: true})
	target, err := app.prepareBundle(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(target)
	out := t.TempDir()
	if err := app.runStaticOutputs(context.Background(), target, out); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(out, "static_outputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stages []staticOutputStage
	if err = json.Unmarshal(manifest, &stages); err != nil || len(stages) != 2 {
		t.Fatalf("%s %v", manifest, err)
	}
	if _, err = os.Stat(filepath.Join(out, "bundles/test.js.export/original.js")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(out, "bundle_patches/test.js.report/jspatch.json")); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(input)
	if !bytes.Equal(original, data) {
		t.Fatal("input modified")
	}
	os.RemoveAll(target)
	if _, err = os.Stat(filepath.Join(out, "bundles/test.js.export/original.js")); err != nil {
		t.Fatal("result lost with upload cleanup")
	}
	if len(app.bundleFindings) == 0 {
		t.Fatal("standalone bundle findings missing")
	}
}
func TestStaticSaveDecodedDEXIncludesSmali(t *testing.T) {
	dex, _, err := apkloader.AssembleSmaliText("Value.smali", `.class public Lexample/Value;
.super Ljava/lang/Object;
.method public static value()I
    .registers 1
    const/4 v0, 7
    return v0
.end method
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "classes.dex")
	os.WriteFile(input, dex, 0600)
	app := staticTestApp(&CLIOptions{Target: input, SaveDecoded: true, Standalone: true, DexBackend: "native", JavaView: true})
	out := t.TempDir()
	if err := app.runStaticOutputs(context.Background(), t.TempDir(), out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "decoded/smali/example/Value.smali")); err != nil {
		t.Fatal(err)
	}
	foundJava := false
	filepath.WalkDir(filepath.Join(out, "decoded"), func(p string, e os.DirEntry, err error) error {
		if filepath.Ext(p) == ".java" {
			foundJava = true
		}
		return nil
	})
	if !foundJava {
		t.Fatal("Java pseudocode not written")
	}
}
func TestStaticDecodeFailureStillHasManifest(t *testing.T) {
	app := staticTestApp(&CLIOptions{Target: filepath.Join(t.TempDir(), "missing.apk"), SaveDecoded: true})
	out := t.TempDir()
	if err := app.runStaticOutputs(context.Background(), t.TempDir(), out); err == nil {
		t.Fatal("decode failure hidden")
	}
	data, err := os.ReadFile(filepath.Join(out, "static_outputs.json"))
	if err != nil || !bytes.Contains(data, []byte(`"failed"`)) {
		t.Fatalf("failure manifest: %s %v", data, err)
	}
}
func TestStaticOutputFlagsParse(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{"-t", "test.apk", "-bundle-export", "-bundle-patches", "-save-decoded", "-java-view"})
	if err != nil || !opts.BundleExport || !opts.BundlePatches || !opts.SaveDecoded || !opts.JavaView {
		t.Fatalf("flags: %+v %v", opts, err)
	}
}

func TestStaticBundlePatchesSkipUnity(t *testing.T) {
	input := filepath.Join(t.TempDir(), "game.bundle")
	os.WriteFile(input, []byte("UnityFS\x00binary data"), 0600)
	app := staticTestApp(&CLIOptions{Target: input, BundlePatches: true})
	target, err := app.prepareBundle(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(target)
	out := t.TempDir()
	if err := app.runStaticOutputs(context.Background(), target, out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(out, "static_outputs.json"))
	if !bytes.Contains(data, []byte(`"unsupported"`)) {
		t.Fatalf("binary patching not skipped: %s", data)
	}
	if _, err := os.Stat(filepath.Join(out, "bundle_patches")); !os.IsNotExist(err) {
		t.Fatal("binary asset text-patched")
	}
}
