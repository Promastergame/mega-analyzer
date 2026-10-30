package threedee

import (
	"bufio"
	"bytes"
	"math"
	"strconv"
	"strings"
)

// analyzeOBJ counts vertices/faces and computes a bounding box.
func analyzeOBJ(data []byte) Metadata {
	meta := Metadata{Format: "obj"}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	minX, minY, minZ := math.Inf(1), math.Inf(1), math.Inf(1)
	maxX, maxY, maxZ := math.Inf(-1), math.Inf(-1), math.Inf(-1)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "v "):
			meta.Vertices++
			fields := strings.Fields(line[2:])
			if len(fields) >= 3 {
				x, _ := strconv.ParseFloat(fields[0], 64)
				y, _ := strconv.ParseFloat(fields[1], 64)
				z, _ := strconv.ParseFloat(fields[2], 64)
				if x < minX {
					minX = x
				}
				if y < minY {
					minY = y
				}
				if z < minZ {
					minZ = z
				}
				if x > maxX {
					maxX = x
				}
				if y > maxY {
					maxY = y
				}
				if z > maxZ {
					maxZ = z
				}
			}
		case strings.HasPrefix(line, "f "):
			meta.Faces++
		}
	}
	if meta.Vertices > 0 && !math.IsInf(minX, 1) {
		meta.BBoxMin = [3]float64{minX, minY, minZ}
		meta.BBoxMax = [3]float64{maxX, maxY, maxZ}
	}
	return meta
}
