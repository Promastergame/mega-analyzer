package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestProgressHarnessOnSyntheticProject(t *testing.T) {
	root := testutil.TempDir(t)
	// More than one file makes the progress callback and delta loop execute.
	for _, name := range []string{"First", "Second", "Third"} {
		source := ".class public Lfixture/" + name + ";\n.super Ljava/lang/Object;\n.method public static f()V\n .registers 0\n return-void\n.end method\n"
		if err := os.WriteFile(filepath.Join(root, name+".smali"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := os.Args
	os.Args = []string{"progresscheck", root}
	defer func() { os.Args = old }()
	out := testutil.CaptureStdout(t, main)
	for _, part := range []string{"=== PROGRESS TICKS ===", "tick ", "max delta between updates:", "total matches:", "files: 3"} {
		if !strings.Contains(out, part) {
			t.Errorf("missing %q in %s", part, out)
		}
	}
}
