package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindAPKEditorBinarySeparateRepository(t *testing.T) {
	name := "apk-editor"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, tc := range []struct {
		name, cwd, analyzer, editor string
	}{
		{"sibling from working directory", "mega-analyzer", "elsewhere/analyzer", "apk-editor/zig-out/bin"},
		{"sibling from analyzer root", "unrelated", "mega-analyzer/analyzer", "apk-editor"},
		{"sibling from analyzer bin", "unrelated", "mega-analyzer/bin/analyzer", "apk-editor/zig-out/bin"},
		{"adjacent portable install", "unrelated", "portable/analyzer", "portable"},
		{"working directory bin", "workspace", "elsewhere/analyzer", "workspace/bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", "")
			root := t.TempDir()
			want := filepath.Join(root, tc.editor, name)
			if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(want, []byte("fixture"), 0o755); err != nil {
				t.Fatal(err)
			}
			got, err := findAPKEditorBinary(filepath.Join(root, tc.cwd), filepath.Join(root, tc.analyzer), "")
			if err != nil || got != want {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestFindAPKEditorBinaryOverride(t *testing.T) {
	t.Setenv("PATH", "")
	root := t.TempDir()
	want := filepath.Join(root, "custom editor.exe")
	if err := os.WriteFile(want, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findAPKEditorBinary(root, "", want)
	if err != nil || got != want {
		t.Fatalf("override: got %q, %v; want %q", got, err, want)
	}
	for _, invalid := range []string{root, filepath.Join(root, "missing.exe")} {
		if _, err := findAPKEditorBinary(root, "", invalid); err == nil || !strings.Contains(err.Error(), "APK_EDITOR_EXE") {
			t.Fatalf("invalid override %q: got %v", invalid, err)
		}
	}
}

func TestFindAPKEditorBinarySkipsDirectory(t *testing.T) {
	t.Setenv("PATH", "")
	root := t.TempDir()
	name := "apk-editor"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.MkdirAll(filepath.Join(root, "bin", name), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := findAPKEditorBinary(root, "", ""); err == nil {
		t.Fatal("directory must not be returned as an editor executable")
	}
}
