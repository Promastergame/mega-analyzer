package threedee

import "bytes"

// analyzeFBX is a binary header sniff. Full FBX parsing is out of scope —
// plan §7 explicitly says we don't ship a full FBX parser. Returning the
// format alone is sufficient for the artifact card.
func analyzeFBX(data []byte) Metadata {
	meta := Metadata{Format: "fbx"}
	if bytes.HasPrefix(data, []byte("Kaydara FBX Binary")) {
		return meta
	}
	// ASCII FBX starts with ; FBX or FBXHeader
	if bytes.Contains(data[:min(len(data), 256)], []byte("FBX")) {
		return meta
	}
	return Metadata{}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
