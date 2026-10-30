package threedee

import (
	"mega-analyzer/pkg/ml/media3d"
)

// glTF and GLB parsing lives in pkg/ml/media3d. This file is the adapter that
// keeps the Metadata shape the artifacts pipeline already consumes.
//
// There used to be a second, independent GLB reader here and a third one in
// zig/apk_editor. Three implementations of a format that gains extensions every
// year is three chances to disagree, and they did: this one recognised only a
// chunk tagged "JSON" and returned an empty Metadata for any container that
// leads with a vendor chunk, which is exactly how Supercell ships Brawl Stars
// models. One reader now serves the pipeline, the CLI and the editor.

// analyzeGLTF parses a glTF 2.0 JSON document (.gltf).
func analyzeGLTF(data []byte) Metadata {
	meta := Metadata{Format: "gltf"}
	doc, err := media3d.ParseDocument(data)
	if err != nil {
		return meta
	}
	meta.Vertices, meta.Faces, _ = doc.Geometry()
	return meta
}

// analyzeGLB parses the binary GLB container and derives metadata from
// whichever JSON chunk it finds, wherever it sits.
//
// The format tag is set unconditionally: a caller that reached this function
// asked about a GLB, and reporting "not a model" for a truncated or vendor
// container would lose the fact that the file was a GLB at all.
func analyzeGLB(data []byte) Metadata {
	r := media3d.Probe(data)
	return Metadata{
		Format:   "glb",
		Vertices: r.Vertices,
		Faces:    r.Faces,
	}
}

// ProbeGLTF exposes the full container report: chunk table, extension census,
// anomalies and the stock-loadability verdict. Analyze deliberately returns
// only the narrow Metadata the report renderer needs, so anything that wants
// the detail calls this instead of re-parsing.
func ProbeGLTF(data []byte) media3d.Report {
	return media3d.Probe(data)
}
