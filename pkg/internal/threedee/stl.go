package threedee

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
)

// analyzeSTL detects ASCII vs binary STL and counts triangles.
func analyzeSTL(data []byte) Metadata {
	meta := Metadata{Format: "stl"}
	if len(data) < 84 {
		// must at least be a binary header
		if isASCIISTL(data) {
			return countASCIISTL(data)
		}
		return meta
	}
	// Try binary first — header(80) + uint32 count + 50*count facets.
	count := binary.LittleEndian.Uint32(data[80:84])
	expected := 84 + int(count)*50
	if expected > 0 && expected <= len(data) && count > 0 {
		meta.Triangles = int(count)
		meta.Faces = int(count)
		return meta
	}
	if isASCIISTL(data) {
		return countASCIISTL(data)
	}
	return meta
}

func isASCIISTL(data []byte) bool {
	head := data
	if len(head) > 256 {
		head = head[:256]
	}
	return bytes.HasPrefix(bytes.TrimSpace(head), []byte("solid"))
}

func countASCIISTL(data []byte) Metadata {
	meta := Metadata{Format: "stl"}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		if strings.HasPrefix(strings.TrimSpace(scanner.Text()), "facet normal") {
			meta.Triangles++
			meta.Faces++
		}
	}
	return meta
}
