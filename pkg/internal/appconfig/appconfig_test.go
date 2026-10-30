package appconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitConfigRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvDir, "  "+root+" \t")
	if got := BaseDir(); got != root {
		t.Fatalf("root=%q, want %q", got, root)
	}
	for _, rel := range []string{"configs/rules.json", "configs/../configs/a b.json", ""} {
		if got, want := Path(rel), filepath.Join(root, filepath.FromSlash(rel)); got != want {
			t.Errorf("Path(%q)=%q, want %q", rel, got, want)
		}
	}
	abs := filepath.Join(t.TempDir(), "external.json")
	if Path(abs) != abs {
		t.Fatal("absolute override was rebased")
	}
}

func TestDefaultConfigRoot(t *testing.T) {
	t.Setenv(EnvDir, " \t ")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want := "."
	if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "configs")); err == nil {
		want = filepath.Dir(exe)
	}
	if got := BaseDir(); got != want {
		t.Fatalf("root=%q, want %q", got, want)
	}
}
