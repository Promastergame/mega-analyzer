package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/testutil"
)

func TestRenderManifestCommand(t *testing.T) {
	path := filepath.Join(testutil.TempDir(t), "manifest.axml")
	if err := os.WriteFile(path, axml.MinimalManifestXML(), 0600); err != nil {
		t.Fatal(err)
	}
	old := os.Args
	os.Args = []string{"tmp_axml", path}
	defer func() { os.Args = old }()
	out := testutil.CaptureStdout(t, main)
	if !strings.Contains(out, "com.example") || !strings.Contains(out, "android.permission.INTERNET") {
		t.Fatalf("rendered manifest=%s", out)
	}
}

func TestRenderCommandPanicsOnInvalidInput(t *testing.T) {
	bad := filepath.Join(testutil.TempDir(t), "bad.axml")
	if err := os.WriteFile(bad, []byte("not axml"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{bad, bad + ".missing"} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			old := os.Args
			os.Args = []string{"tmp_axml", path}
			defer func() { os.Args = old }()
			defer func() {
				if recover() == nil {
					t.Error("invalid input did not panic")
				}
			}()
			main()
		})
	}
}
