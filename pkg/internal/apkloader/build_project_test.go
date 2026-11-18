package apkloader

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func writeProjectZIP(t *testing.T, members map[string]string) string {
	t.Helper()
	path := filepath.Join(testutil.TempDir(t), "project.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, data := range members {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrepareBuildProjectZIP(t *testing.T) {
	for _, prefix := range []string{"", "download/decoded/"} {
		t.Run(prefix, func(t *testing.T) {
			input := writeProjectZIP(t, map[string]string{
				prefix + "AndroidManifest.xml": "<manifest package=\"com.example.app\"/>",
				prefix + "smali/A.smali":       ".class public LA;\n.super Ljava/lang/Object;\n",
				prefix + "smali/A.java":        "pseudocode sidecar",
				prefix + "assets/sample.kt":    "application payload",
			})
			dir, cleanup, err := PrepareBuildProject(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if data, err := os.ReadFile(filepath.Join(dir, "smali/A.smali")); err != nil || !strings.Contains(string(data), "LA;") {
				t.Fatalf("project edits missing: %s %v", data, err)
			}
			cleanup()
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("staging not removed: %v", err)
			}
			if _, err := os.Stat(input); err != nil {
				t.Fatalf("input was removed: %v", err)
			}
		})
	}
}

func TestPrepareBuildProjectRejectsIncompleteOrUnsupportedZIP(t *testing.T) {
	tests := []struct {
		name    string
		members map[string]string
		want    string
	}{
		{"traversal", map[string]string{"../outside": "x", "AndroidManifest.xml": "x"}, "unsafe"},
		{"backslash", map[string]string{"project\\AndroidManifest.xml": "x"}, "unsafe"},
		{"multiple", map[string]string{"a/AndroidManifest.xml": "x", "b/AndroidManifest.xml": "x"}, "exactly one"},
		{"no manifest", map[string]string{"smali/A.smali": "x"}, "exactly one"},
		{"java source", map[string]string{"AndroidManifest.xml": "x", "src/A.java": "x"}, "Java/Kotlin"},
		{"gradle", map[string]string{"AndroidManifest.xml": "x", "build.gradle.kts": "x"}, "Java/Kotlin"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, cleanup, err := PrepareBuildProject(context.Background(), writeProjectZIP(t, tc.members))
			cleanup()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPrepareBuildProjectCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, cleanup, err := PrepareBuildProject(ctx, "missing.zip")
	cleanup()
	if err != context.Canceled {
		t.Fatalf("error = %v", err)
	}
}
