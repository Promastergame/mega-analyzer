package threedee

import "bytes"

// analyzeDAE just confirms the COLLADA root tag. Vertex / face counts in
// COLLADA require a full XML traversal and aren't worth the dependency
// for a card-level summary.
func analyzeDAE(data []byte) Metadata {
	meta := Metadata{Format: "dae"}
	if !bytes.Contains(data[:min(len(data), 1024)], []byte("<COLLADA")) {
		return Metadata{}
	}
	return meta
}
