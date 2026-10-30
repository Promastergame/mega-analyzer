package threedee

import "testing"

func TestDetectByExt(t *testing.T) {
	cases := map[string]string{
		"a.obj":  "obj",
		"a.gltf": "gltf",
		"a.glb":  "glb",
		"a.fbx":  "fbx",
		"a.dae":  "dae",
		"a.stl":  "stl",
		"a.png":  "",
	}
	for path, want := range cases {
		got := Detect(nil, path)
		if got != want {
			t.Fatalf("Detect(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestAnalyzeOBJCounts(t *testing.T) {
	data := []byte("# test\nv 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n")
	meta := Analyze(data, ".obj")
	if meta.Vertices != 3 {
		t.Fatalf("expected 3 vertices, got %d", meta.Vertices)
	}
	if meta.Faces != 1 {
		t.Fatalf("expected 1 face, got %d", meta.Faces)
	}
	if meta.BBoxMin[0] != 0 || meta.BBoxMax[0] != 1 {
		t.Fatalf("bbox wrong: %v %v", meta.BBoxMin, meta.BBoxMax)
	}
}

func TestAnalyzeSTLBinary(t *testing.T) {
	header := make([]byte, 84)
	// triangles count = 1
	header[80] = 1
	body := make([]byte, 50)
	data := append(header, body...)
	meta := Analyze(data, ".stl")
	if meta.Triangles != 1 {
		t.Fatalf("expected 1 triangle, got %d", meta.Triangles)
	}
}

func TestAnalyzeGLBHeader(t *testing.T) {
	// Minimal GLB header that doesn't include a JSON chunk — should not panic.
	header := []byte{'g', 'l', 'T', 'F', 2, 0, 0, 0, 0x14, 0, 0, 0}
	meta := Analyze(header, ".glb")
	if meta.Format != "glb" {
		t.Fatalf("expected glb format, got %q", meta.Format)
	}
}

func TestAnalyzePanicSafeOnGarbage(t *testing.T) {
	// Random garbage with .obj extension should not panic.
	_ = Analyze([]byte{0xFF, 0xFE, 0xFD}, ".obj")
}
