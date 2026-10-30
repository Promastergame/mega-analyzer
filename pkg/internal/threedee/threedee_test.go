package threedee

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestIsThreeDee(t *testing.T) {
	if !IsThreeDee(nil, "model.obj") {
		t.Error(".obj should be recognised")
	}
	if IsThreeDee([]byte("hello"), ".txt") {
		t.Error(".txt should NOT be recognised")
	}
	// glb magic-byte detection without an extension.
	if !IsThreeDee([]byte("glTF\x02\x00\x00\x00"), "") {
		t.Error("glTF magic should be detected without ext")
	}
}

func TestDetectAllExtensions(t *testing.T) {
	cases := map[string]string{
		"obj": "obj", "gltf": "gltf", "glb": "glb",
		"fbx": "fbx", "dae": "dae", "stl": "stl",
		"ply": "ply", "3ds": "3ds",
		"unknown": "",
	}
	for ext, want := range cases {
		if got := Detect(nil, ext); got != want {
			t.Errorf("Detect(nil, %q) = %q, want %q", ext, got, want)
		}
	}

	// Path with directory components and full filename.
	if got := Detect(nil, "models/sub/spaceship.OBJ"); got != "obj" {
		t.Errorf("path-based detect failed: got %q", got)
	}
}

func TestDetectMagicBytes(t *testing.T) {
	// glTF binary magic
	if got := Detect([]byte("glTF\x02\x00\x00\x00"), ""); got != "glb" {
		t.Errorf("glTF magic not detected, got %q", got)
	}
	// Kaydara FBX binary magic
	if got := Detect([]byte("Kaydara FBX Binary  \x00"), ""); got != "fbx" {
		t.Errorf("FBX magic not detected, got %q", got)
	}
	// Random input → empty.
	if got := Detect([]byte{1, 2, 3, 4}, ""); got != "" {
		t.Errorf("random data should not match, got %q", got)
	}
}

func TestAnalyzeDispatchesToRightParser(t *testing.T) {
	if got := Analyze([]byte("v 1 2 3\nf 1 2 3\n"), "x.obj"); got.Format != "obj" {
		t.Errorf("OBJ analyze didn't pick obj, got %+v", got)
	}
	if got := Analyze([]byte("nothing"), "x.ply"); got.Format != "ply" {
		t.Errorf("PLY ext should yield format=ply, got %+v", got)
	}
	// Unknown ext → zero metadata.
	if got := Analyze([]byte("nothing"), "x.unknown"); got.Format != "" {
		t.Errorf("unknown ext should be zero metadata, got %+v", got)
	}
}

func TestAnalyzeFBXMagic(t *testing.T) {
	got := Analyze([]byte("Kaydara FBX Binary  \x00\x00"), "x.fbx")
	if got.Format != "fbx" {
		t.Errorf("FBX magic not analyzed, got %+v", got)
	}
}

func TestAnalyzeFBXAsciiHint(t *testing.T) {
	// ASCII FBX with FBX header keyword.
	got := analyzeFBX([]byte("; FBX 7.4.0 project file\n"))
	if got.Format != "fbx" {
		t.Errorf("ASCII FBX analyse failed: %+v", got)
	}
}

func TestAnalyzeFBXEmptyReturnsZero(t *testing.T) {
	if got := analyzeFBX([]byte("nothing here at all")); got.Format != "" {
		t.Errorf("non-FBX must yield empty Metadata, got %+v", got)
	}
}

func TestAnalyzeDAEMatch(t *testing.T) {
	xml := `<?xml version="1.0"?><COLLADA xmlns="...">`
	if got := analyzeDAE([]byte(xml)); got.Format != "dae" {
		t.Errorf("COLLADA root not detected, got %+v", got)
	}
	if got := analyzeDAE([]byte("<svg>...")); got.Format != "" {
		t.Errorf("non-COLLADA should yield empty: %+v", got)
	}
}

func TestAnalyzeOBJ(t *testing.T) {
	// Three vertices + one triangle face.
	src := strings.Join([]string{
		"# blender export",
		"v 0 0 0",
		"v 1 0 0",
		"v 0 1 0",
		"f 1 2 3",
	}, "\n")
	got := analyzeOBJ([]byte(src))
	if got.Vertices != 3 {
		t.Errorf("Vertices = %d, want 3", got.Vertices)
	}
	if got.Faces != 1 {
		t.Errorf("Faces = %d, want 1", got.Faces)
	}
}

func TestAnalyzeSTLBinaryV2(t *testing.T) {
	header := make([]byte, 80)
	body := make([]byte, 0, 84+50*2)
	body = append(body, header...)
	body = binary.LittleEndian.AppendUint32(body, 2) // 2 facets
	body = append(body, make([]byte, 50*2)...)
	got := analyzeSTL(body)
	if got.Triangles != 2 {
		t.Errorf("Triangles = %d, want 2", got.Triangles)
	}
	if got.Format != "stl" {
		t.Errorf("Format = %q", got.Format)
	}
}

func TestAnalyzeSTLAscii(t *testing.T) {
	src := []byte(`solid demo
facet normal 0 0 1
  outer loop
    vertex 0 0 0
    vertex 1 0 0
    vertex 0 1 0
  endloop
endfacet
facet normal 0 1 0
  outer loop
    vertex 0 0 0
    vertex 1 0 0
    vertex 0 0 1
  endloop
endfacet
endsolid demo
`)
	got := analyzeSTL(src)
	if got.Triangles != 2 {
		t.Errorf("ASCII STL triangles = %d, want 2", got.Triangles)
	}
}

func TestAnalyzeSTLTooShort(t *testing.T) {
	if got := analyzeSTL([]byte("solid x\n")); got.Format != "stl" {
		t.Errorf("short ASCII STL should still report stl format, got %+v", got)
	}
	if got := analyzeSTL([]byte{0x00}); got.Format != "stl" {
		t.Errorf("byte-noise should still yield stl format only, got %+v", got)
	}
}

func TestIsAndCountASCIISTL(t *testing.T) {
	if !isASCIISTL([]byte("  solid foo")) {
		t.Error("trimmed solid should be detected")
	}
	if isASCIISTL([]byte("nope")) {
		t.Error("non-solid should not be ASCII STL")
	}
	got := countASCIISTL([]byte("solid x\nfacet normal 0 0 1\nfacet normal 0 0 1\n"))
	if got.Triangles != 2 {
		t.Errorf("count = %d, want 2", got.Triangles)
	}
}

func TestAnalyzeGLTFParsesMeshAccessors(t *testing.T) {
	json := `{
		"accessors": [
			{"count": 24, "type": "VEC3"},
			{"count": 36, "type": "SCALAR"}
		],
		"meshes": [
			{"primitives": [
				{"attributes": {"POSITION": 0}, "indices": 1}
			]}
		]
	}`
	got := analyzeGLTF([]byte(json))
	if got.Vertices != 24 {
		t.Errorf("Vertices = %d, want 24", got.Vertices)
	}
	if got.Faces != 12 {
		t.Errorf("Faces = %d, want 12 (36/3)", got.Faces)
	}
}

func TestAnalyzeGLTFInvalidJSON(t *testing.T) {
	got := analyzeGLTF([]byte("not json"))
	if got.Format != "gltf" {
		t.Errorf("format should still be gltf, got %+v", got)
	}
	if got.Vertices != 0 {
		t.Errorf("invalid JSON should yield zero vertices, got %d", got.Vertices)
	}
}

func TestAnalyzeGLB(t *testing.T) {
	jsonChunk := []byte(`{
		"accessors": [{"count": 8, "type": "VEC3"}],
		"meshes": [{"primitives": [{"attributes": {"POSITION": 0}}]}]
	}`)
	// Pad jsonChunk to multiple of 4.
	for len(jsonChunk)%4 != 0 {
		jsonChunk = append(jsonChunk, 0x20)
	}

	var buf bytes.Buffer
	buf.WriteString("glTF")
	buf.Write([]byte{0x02, 0, 0, 0}) // version 2
	totalLen := uint32(12 + 8 + len(jsonChunk))
	binary.Write(&buf, binary.LittleEndian, totalLen)
	binary.Write(&buf, binary.LittleEndian, uint32(len(jsonChunk)))
	buf.WriteString("JSON")
	buf.Write(jsonChunk)

	got := analyzeGLB(buf.Bytes())
	if got.Format != "glb" {
		t.Errorf("Format = %q, want glb", got.Format)
	}
	if got.Vertices != 8 {
		t.Errorf("Vertices = %d, want 8", got.Vertices)
	}
}

func TestAnalyzeGLBBadMagic(t *testing.T) {
	if got := analyzeGLB([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}); got.Format != "glb" {
		t.Errorf("bad magic should still tag format=glb, got %+v", got)
	}
	// Truncated chunk header → break out cleanly.
	if got := analyzeGLB([]byte("glTF\x00\x00\x00\x00\x00\x00\x00\x00")); got.Format != "glb" {
		t.Errorf("truncated GLB must still report glb format, got %+v", got)
	}
}

func TestMinHelper(t *testing.T) {
	if got := min(3, 7); got != 3 {
		t.Errorf("min(3,7) = %d, want 3", got)
	}
	if got := min(7, 3); got != 3 {
		t.Errorf("min(7,3) = %d, want 3", got)
	}
}
