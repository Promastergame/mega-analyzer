package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

// minimal valid PNG (8x8 magic + IHDR + IEND).
var pngBytes = []byte{
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
	0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
	0x08, 0x02, 0x00, 0x00, 0x00,
	0, 0, 0, 0, // CRC
	0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D',
	0, 0, 0, 0, // CRC
}

func makeFakeAPK(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// smali should be skipped
	smali := filepath.Join(dir, "smali", "com", "x", "Y.smali")
	if err := os.MkdirAll(filepath.Dir(smali), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(smali, []byte(".class Lcom/x/Y;"), 0644)

	// image artifact
	img := filepath.Join(dir, "res", "drawable", "icon.png")
	os.MkdirAll(filepath.Dir(img), 0755)
	os.WriteFile(img, pngBytes, 0644)

	// 3D artifact
	obj := filepath.Join(dir, "assets", "scene.obj")
	os.MkdirAll(filepath.Dir(obj), 0755)
	os.WriteFile(obj, []byte("v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n"), 0644)

	// generic non-smali file
	other := filepath.Join(dir, "META-INF", "weird.unknown")
	os.MkdirAll(filepath.Dir(other), 0755)
	os.WriteFile(other, []byte("payload"), 0644)

	return dir
}

func TestPipelineBuildSkipsSmali(t *testing.T) {
	dir := makeFakeAPK(t)
	out := t.TempDir()

	view, err := Build(Options{
		ExtractedDir: dir,
		OutputDir:    out,
		MaxFileMB:    10,
		BudgetMB:     200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if view == nil {
		t.Fatal("expected non-nil view")
	}
	for _, item := range view.Items {
		if item.Type == "" {
			t.Fatalf("item without type: %+v", item)
		}
		if item.Path == "" {
			t.Fatal("item without path")
		}
	}
	if view.Summary.ByType["image"] != 1 {
		t.Fatalf("expected 1 image, got %d", view.Summary.ByType["image"])
	}
	if view.Summary.ByType["model3d"] != 1 {
		t.Fatalf("expected 1 model3d, got %d", view.Summary.ByType["model3d"])
	}
}

func TestPipelineDisabledReturnsNil(t *testing.T) {
	view, err := Build(Options{}) // no extracted dir
	if err != nil {
		t.Fatal(err)
	}
	if view != nil {
		t.Fatalf("expected nil view, got %+v", view)
	}
}
