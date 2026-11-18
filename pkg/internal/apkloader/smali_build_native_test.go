package apkloader

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/testutil"
)

func TestNativeBuildMultiDEXWithoutTools(t *testing.T) {
	root := testutil.TempDir(t)
	t.Setenv("PATH", "")
	t.Setenv("MEGA_STANDALONE", "")
	toolsDir := filepath.Join(root, "unused-tools")
	t.Setenv("MEGA_TOOLS_DIR", toolsDir)
	for _, dir := range []string{"smali", "smali_classes2"} {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "Hello.smali"), []byte(nativeHelloSmali), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := SmaliBuildConfig{Jobs: 2}
	opts := SmaliBuildOptions{Incremental: true}
	paths, warnings, err := BuildDEXFromSmaliContextWithWarnings(t.Context(), root, cfg, opts)
	if err != nil || len(paths) != 2 {
		t.Fatalf("multidex assembly: paths=%v warnings=%v err=%v", paths, warnings, err)
	}
	untouched := filepath.Join(root, "classes2.dex")
	stamp := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(untouched, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	edited := strings.ReplaceAll(nativeHelloSmali, `= "hello"`, `= "edited"`)
	if err := os.WriteFile(filepath.Join(root, "smali", "Hello.smali"), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, _, err = BuildDEXFromSmaliContextWithWarnings(t.Context(), root, cfg, opts)
	if err != nil || len(paths) != 2 {
		t.Fatalf("incremental assembly: paths=%v err=%v", paths, err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		parser, err := ParseDEXBytes(data)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		class := parser.FindClassByName("Lcom/example/Hello;")
		if class == nil {
			t.Fatalf("class missing in %s", path)
		}
		values, err := parser.decodeStaticValues(class, 8, 65536, 1<<20)
		parser.Close()
		want := "hello"
		if filepath.Base(path) == "classes.dex" {
			want = "edited"
		}
		if err != nil || values["Lcom/example/Hello;->TAG:Ljava/lang/String;"].String != want {
			t.Fatalf("stale field value in %s: %v err=%v", path, values, err)
		}
	}
	info, err := os.Stat(untouched)
	if err != nil || !info.ModTime().Equal(stamp) {
		t.Fatalf("incremental assembly rewrote the unchanged DEX: %v, %v", info, err)
	}
	if _, err := os.Stat(toolsDir); !os.IsNotExist(err) {
		t.Fatalf("native assembly created an external-tool cache: %v", err)
	}
}

func TestNativeBuildErrorsDoNotReturnPartialDEX(t *testing.T) {
	root := testutil.TempDir(t)
	if err := os.MkdirAll(filepath.Join(root, "smali"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "smali_classes2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "smali_classes2", "Hello.smali"), []byte(nativeHelloSmali), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, _, err := BuildDEXFromSmaliContextWithWarnings(t.Context(), root, SmaliBuildConfig{Jobs: 2}, SmaliBuildOptions{Incremental: true})
	var unsupported *nativeUnsupportedError
	if len(paths) != 0 || !errors.As(err, &unsupported) || !strings.Contains(err.Error(), "no .smali files") {
		t.Fatalf("unsupported input must remain a native error: paths=%v err=%v", paths, err)
	}
	if len(loadSmaliBuildCache(root).Entries) != 0 {
		t.Fatal("failed assembly saved a successful incremental cache")
	}
}

func TestCancelledNativeBuildDoesNotWriteDEX(t *testing.T) {
	root := testutil.TempDir(t)
	if err := os.MkdirAll(filepath.Join(root, "smali"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "smali", "Hello.smali"), []byte(nativeHelloSmali), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	paths, err := BuildDEXFromSmaliContext(ctx, root, SmaliBuildConfig{}, SmaliBuildOptions{})
	if len(paths) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled assembly: paths=%v err=%v", paths, err)
	}
	if _, err := os.Stat(filepath.Join(root, "classes.dex")); !os.IsNotExist(err) {
		t.Fatalf("cancelled assembly wrote a DEX: %v", err)
	}
}
