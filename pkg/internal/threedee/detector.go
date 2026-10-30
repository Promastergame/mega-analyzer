package threedee

import (
	"bytes"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// 3D ARTIFACT DETECTOR
//
// Lightweight magic / extension dispatcher. The individual format files
// produce a Metadata struct with as much info as we can extract WITHOUT
// rendering. Plan §7 explicitly forbids three.js previews.
// ═══════════════════════════════════════════════════════════════════════════════

// Metadata holds per-file 3D info.
type Metadata struct {
	Format    string
	Vertices  int
	Faces     int
	Triangles int
	BBoxMin   [3]float64
	BBoxMax   [3]float64
}

// IsThreeDee returns true when the extension or magic identifies a 3D model.
func IsThreeDee(data []byte, ext string) bool {
	return Detect(data, ext) != ""
}

// Detect returns the canonical format string ("obj", "gltf", ...) or "".
//
// The ext argument may be either ".gltf", "gltf" or a path like "x/y.gltf";
// in all cases we use the part after the last dot.
func Detect(data []byte, ext string) string {
	if i := strings.LastIndexByte(ext, '.'); i >= 0 {
		ext = ext[i+1:]
	}
	ext = strings.ToLower(ext)
	switch ext {
	case "obj":
		return "obj"
	case "gltf":
		return "gltf"
	case "glb":
		return "glb"
	case "fbx":
		return "fbx"
	case "dae":
		return "dae"
	case "stl":
		return "stl"
	case "ply":
		return "ply"
	case "3ds":
		return "3ds"
	}
	if len(data) >= 4 {
		switch {
		case bytes.Equal(data[:4], []byte("glTF")):
			return "glb"
		case bytes.HasPrefix(data, []byte("Kaydara FBX Binary")):
			return "fbx"
		}
	}
	return ""
}

// Analyze returns metadata for the detected format. Always panic-safe.
func Analyze(data []byte, ext string) Metadata {
	defer func() { notePanic("threedee.detector", recover()) }()

	format := Detect(data, ext)
	switch format {
	case "obj":
		return analyzeOBJ(data)
	case "gltf":
		return analyzeGLTF(data)
	case "glb":
		return analyzeGLB(data)
	case "fbx":
		return analyzeFBX(data)
	case "dae":
		return analyzeDAE(data)
	case "stl":
		return analyzeSTL(data)
	}
	if format != "" {
		return Metadata{Format: format}
	}
	return Metadata{}
}
