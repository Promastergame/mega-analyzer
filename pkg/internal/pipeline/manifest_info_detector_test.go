// pkg/internal/pipeline/manifest_info_detector_test.go
package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func manifestTestCtx(path, content string) (*FileDetectContext, *types.FileAnalysis) {
	data := []byte(content)
	ctx := &FileDetectContext{
		Path:        path,
		FileType:    types.FileTypeXML,
		Content:     data,
		LineOffsets: types.NewLineOffsets(data),
	}
	analysis := &types.FileAnalysis{Path: path}
	return ctx, analysis
}

func findMatchByPattern(matches []types.Match, pattern string) *types.Match {
	for i := range matches {
		if matches[i].Pattern == pattern {
			return &matches[i]
		}
	}
	return nil
}

func TestManifestInfoDetector_SkipsNonXML(t *testing.T) {
	d := NewManifestInfoDetector()
	ctx := &FileDetectContext{
		Path:        "AndroidManifest.xml",
		FileType:    types.FileTypeSmali,
		Content:     []byte(`<manifest package="com.test"></manifest>`),
		LineOffsets: types.NewLineOffsets([]byte("x")),
	}
	a := &types.FileAnalysis{Path: ctx.Path}
	d.Detect(ctx, a)
	if len(a.Matches) != 0 {
		t.Fatalf("expected 0 matches for non-XML, got %d", len(a.Matches))
	}
}

func TestManifestInfoDetector_SkipsNonManifestPath(t *testing.T) {
	d := NewManifestInfoDetector()
	ctx, a := manifestTestCtx("res/layout/main.xml", `<manifest package="com.test"></manifest>`)
	d.Detect(ctx, a)
	if len(a.Matches) != 0 {
		t.Fatalf("expected 0 matches for non-manifest path, got %d", len(a.Matches))
	}
}

func TestManifestInfoDetector_MinimalExtraction(t *testing.T) {
	d := NewManifestInfoDetector()
	xml := `<manifest package="com.example.app">
	<application android:label="@string/app_name"></application>
	<uses-permission android:name="android.permission.INTERNET" />
	<uses-permission-sdk-23 android:name="android.permission.CAMERA" />
</manifest>`

	ctx, a := manifestTestCtx("AndroidManifest.xml", xml)
	d.Detect(ctx, a)

	if m := findMatchByPattern(a.Matches, "com.example.app"); m == nil || m.Context != "Manifest package name" {
		t.Fatal("missing package name match")
	}
	if m := findMatchByPattern(a.Matches, "@string/app_name"); m == nil || m.Context != "Application label" {
		t.Fatal("missing application label match")
	}
	if m := findMatchByPattern(a.Matches, "android.permission.INTERNET"); m == nil || m.Context != "Declared permission" {
		t.Fatal("missing INTERNET permission match")
	}
	if m := findMatchByPattern(a.Matches, "android.permission.CAMERA"); m == nil {
		for i := range a.Matches {
			t.Logf("match[%d]: context=%q pattern=%q", i, a.Matches[i].Context, a.Matches[i].Pattern)
		}
		t.Fatal("missing CAMERA permission match (sdk-23)")
	} else if m.Context != "Declared permission" && m.Context != "Dangerous permission (runtime)" {
		t.Fatalf("unexpected CAMERA permission context: %q", m.Context)
	}
}

func TestManifestInfoDetector_PermissionDedup(t *testing.T) {
	d := NewManifestInfoDetector()
	xml := `<manifest package="com.test">
	<uses-permission android:name="android.permission.INTERNET" />
	<uses-permission android:name="android.permission.INTERNET" />
</manifest>`

	ctx, a := manifestTestCtx("AndroidManifest.xml", xml)
	d.Detect(ctx, a)

	count := 0
	for i := range a.Matches {
		if a.Matches[i].Pattern == "android.permission.INTERNET" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected deduped INTERNET permission (1), got %d", count)
	}
}
