package decompiler_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"mega-analyzer/pkg/decompiler"
	"mega-analyzer/pkg/internal/apkloader"
)

func testDEX(t *testing.T, class string) []byte {
	t.Helper()
	source := fmt.Sprintf(`.class public Lexample/%s;
.super Ljava/lang/Object;
.field public static final VALUE:I = 7
.method public static value()I
    .registers 1
    const/4 v0, 7
    return v0
.end method
`, class)
	dex, _, err := apkloader.AssembleSmaliText(class+".smali", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	return dex
}

func zipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeInput(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDecodeStandaloneDEXWithoutTools(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	dex := testDEX(t, "Value")
	input := writeInput(t, filepath.Join(dir, "input.dex"), dex)
	result, err := decompiler.Decode(t.Context(), input, decompiler.Options{
		OutputDir: filepath.Join(dir, "out"), Backend: decompiler.BackendAuto, Standalone: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Backend != decompiler.BackendNative || result.DEXFiles != 1 || result.SmaliFiles != 1 {
		t.Fatalf("unexpected decode result: %+v", result)
	}
	preserved, err := os.ReadFile(filepath.Join(result.OutputDir, "classes.dex"))
	if err != nil || !bytes.Equal(preserved, dex) {
		t.Fatalf("original DEX was not preserved: %v", err)
	}
	smali, err := os.ReadFile(filepath.Join(result.OutputDir, "smali", "example", "Value.smali"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{".class public Lexample/Value;", "VALUE:I = 7", "value()I", "return v0"} {
		if !bytes.Contains(smali, []byte(want)) {
			t.Errorf("Smali is missing %q:\n%s", want, smali)
		}
	}
	if _, err := os.Stat(filepath.Join(result.OutputDir, "REPORT.html")); !os.IsNotExist(err) {
		t.Fatalf("decoding must not run security reporting: %v", err)
	}
}

func TestDecodeMultidexAPK(t *testing.T) {
	dir := t.TempDir()
	input := writeInput(t, filepath.Join(dir, "app.apk"), zipBytes(t, map[string][]byte{
		"AndroidManifest.xml": []byte(`<manifest package="example.app"/>`),
		"classes.dex":         testDEX(t, "First"),
		"classes2.dex":        testDEX(t, "Second"),
		"assets/config.txt":   []byte("fixture"),
	}))
	for _, cache := range []bool{false, true} {
		result, err := decompiler.Decode(t.Context(), input, decompiler.Options{
			OutputDir: filepath.Join(dir, fmt.Sprintf("out-%t", cache)), ClassCache: cache,
		})
		if err != nil || !result.Complete || result.DEXFiles != 2 || result.SmaliFiles != 2 {
			t.Fatalf("class cache %t: %+v, %v", cache, result, err)
		}
		for _, file := range []string{"smali/example/First.smali", "smali_classes2/example/Second.smali", "assets/config.txt", "omnisec-meta.json"} {
			if _, err := os.Stat(filepath.Join(result.OutputDir, filepath.FromSlash(file))); err != nil {
				t.Errorf("class cache %t: %s: %v", cache, file, err)
			}
		}
	}
}

func TestConcurrentDecodeOptionsAreIsolated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MEGA_STANDALONE", "")
	t.Setenv("PATH", dir)
	oldHeaders := apkloader.DisableSmaliHeaders.Load()
	apkloader.DisableSmaliHeaders.Store(false)
	t.Cleanup(func() { apkloader.DisableSmaliHeaders.Store(oldHeaders) })
	input := writeInput(t, filepath.Join(dir, "value.dex"), testDEX(t, "Value"))
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			headers := i%2 == 0
			result, err := decompiler.Decode(t.Context(), input, decompiler.Options{
				OutputDir: filepath.Join(dir, fmt.Sprint(i)), Headers: headers,
				Standalone: headers, ClassCache: true,
			})
			if err != nil {
				t.Errorf("decode %d: %v", i, err)
				return
			}
			data, err := os.ReadFile(filepath.Join(result.OutputDir, "smali/example/Value.smali"))
			if err != nil || bytes.HasPrefix(data, []byte("# Disassembled")) != headers {
				t.Errorf("decode %d: headers should be %t, err=%v, data=%s", i, headers, err, data)
			}
		}(i)
	}
	wg.Wait()
	if apkloader.Standalone() || apkloader.DisableSmaliHeaders.Load() {
		t.Fatal("Decode changed a process-wide policy")
	}
}

func TestHeaderChangeInvalidatesDecodeAndClassCaches(t *testing.T) {
	dir := t.TempDir()
	input := writeInput(t, filepath.Join(dir, "value.dex"), testDEX(t, "Value"))
	for _, headers := range []bool{true, false, true} {
		result, err := decompiler.Decode(t.Context(), input, decompiler.Options{
			OutputDir: filepath.Join(dir, "out"), Headers: headers, ClassCache: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(result.OutputDir, "smali/example/Value.smali"))
		if err != nil || bytes.HasPrefix(data, []byte("# Disassembled")) != headers {
			t.Fatalf("stale cache after changing headers to %t: %v\n%s", headers, err, data)
		}
	}
}

func TestIncompleteDecodeDoesNotLeaveSuccessMarker(t *testing.T) {
	for _, broken := range []string{"dex", "manifest", "arsc", "split"} {
		t.Run(broken, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string][]byte{
				"AndroidManifest.xml": []byte(`<manifest package="example.app"/>`),
				"classes.dex":         testDEX(t, "Value"),
			}
			input := writeInput(t, filepath.Join(dir, "app.apk"), zipBytes(t, files))
			opts := decompiler.Options{OutputDir: filepath.Join(dir, "out")}
			if result, err := decompiler.Decode(t.Context(), input, opts); err != nil || !result.Complete {
				t.Fatalf("initial decode: %+v, %v", result, err)
			}
			switch broken {
			case "dex":
				files["classes.dex"] = []byte("dex\n035\x00broken")
			case "manifest":
				files["AndroidManifest.xml"] = []byte("<manifest>")
			case "arsc":
				files["resources.arsc"] = []byte("broken resource table")
			case "split":
				files = map[string][]byte{"base.apk": zipBytes(t, files), "split.apk": []byte("broken zip")}
			}
			writeInput(t, input, zipBytes(t, files))
			result, err := decompiler.Decode(t.Context(), input, opts)
			if err == nil || result.Complete || result.OutputDir != opts.OutputDir {
				t.Fatalf("partial decode reported success or lost its directory: %+v, %v", result, err)
			}
			if _, err := os.Stat(filepath.Join(opts.OutputDir, ".mega-analyzer-decode-cache.json")); !os.IsNotExist(err) {
				t.Fatalf("partial decode left a success marker: %v", err)
			}
		})
	}
}

func TestDecodeValidationAndCancellationDoNotCreateOutput(t *testing.T) {
	dir := t.TempDir()
	input := writeInput(t, filepath.Join(dir, "value.dex"), testDEX(t, "Value"))
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	cases := []struct {
		name    string
		input   string
		ctx     context.Context
		opts    decompiler.Options
		wantErr error
	}{
		{"cancelled", input, cancelled, decompiler.Options{}, context.Canceled},
		{"missing", filepath.Join(dir, "missing.apk"), t.Context(), decompiler.Options{}, os.ErrNotExist},
		{"directory", dir, t.Context(), decompiler.Options{}, nil},
		{"backend", input, t.Context(), decompiler.Options{Backend: "invalid"}, nil},
		{"retired-backend", input, t.Context(), decompiler.Options{Backend: "baksmali"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.OutputDir = filepath.Join(dir, tc.name+"-out")
			result, err := decompiler.Decode(tc.ctx, tc.input, tc.opts)
			if err == nil || result.Complete || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
				t.Fatalf("invalid input result: %+v, %v", result, err)
			}
			if _, err := os.Stat(tc.opts.OutputDir); !os.IsNotExist(err) {
				t.Fatalf("validation created output: %v", err)
			}
		})
	}
	if _, err := decompiler.Decode(t.Context(), input, decompiler.Options{OutputDir: dir}); err == nil || !strings.Contains(err.Error(), "contain the input") {
		t.Fatalf("must reject input inside its output directory: %v", err)
	}
}
