package media

import (
	"encoding/binary"
)

// MP4Atom describes a parsed MP4/MOV atom (box).
type MP4Atom struct {
	Type     string    `json:"type"`               // "ftyp", "moov", "mdat", etc.
	Size     int       `json:"size"`               // total size including header
	Offset   int       `json:"offset"`             // byte offset in file
	Children []MP4Atom `json:"children,omitempty"` // for container atoms
}

// MP4Threat describes a suspicious element found in an MP4 file.
type MP4Threat struct {
	Type       string  `json:"type"` // "hidden_track", "encrypted", "edit_list_anomaly"
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
}

// AnalyzeMP4 performs deep analysis on an MP4/MOV file, parsing the atom
// tree and looking for hidden tracks, encrypted segments, and anomalies.
func AnalyzeMP4(data []byte) ([]MP4Atom, []MP4Threat) {
	if len(data) < 8 {
		return nil, nil
	}

	atoms := parseMP4Atoms(data, 0, len(data), 0)
	var threats []MP4Threat

	// Detect anomalies
	threats = append(threats, detectMP4Threats(data, atoms)...)

	return atoms, threats
}

// mp4MaxDepth bounds atom-tree recursion so a crafted file with deeply
// nested container atoms cannot exhaust the stack.
const mp4MaxDepth = 32

func parseMP4Atoms(data []byte, start, end, depth int) []MP4Atom {
	var atoms []MP4Atom
	if depth > mp4MaxDepth {
		return atoms
	}
	pos := start

	containerTypes := map[string]bool{
		"moov": true, "trak": true, "mdia": true, "minf": true,
		"stbl": true, "udta": true, "meta": true, "ilst": true,
	}

	for pos+8 <= end && pos+8 <= len(data) {
		size := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		typ := string(data[pos+4 : pos+8])

		// Header size grows to 16 bytes when a 64-bit largesize is used.
		headerSize := 8

		switch {
		case size == 1:
			// 64-bit "largesize": the real size is stored in the 8 bytes
			// immediately following the type field.
			if pos+16 > end || pos+16 > len(data) {
				return atoms // truncated extended-size header
			}
			largeSize := binary.BigEndian.Uint64(data[pos+8 : pos+16])
			if largeSize < 16 || largeSize > uint64(end-pos) {
				// Overflow or nonsense value — treat as "extends to end".
				size = end - pos
			} else {
				size = int(largeSize)
			}
			headerSize = 16
		case size == 0:
			// size == 0 means the atom extends to the end of the file
			// (or the enclosing container).
			size = end - pos
		case size < 8:
			// Invalid/corrupt atom size — stop parsing this level.
			return atoms
		}

		if pos+size > end {
			break
		}

		atom := MP4Atom{
			Type:   typ,
			Size:   size,
			Offset: pos,
		}

		// Parse container atoms recursively. 'meta' carries an extra 4-byte
		// version/flags header before its children.
		childHeader := headerSize
		if typ == "meta" {
			childHeader += 4
		}
		if containerTypes[typ] && size > childHeader {
			atom.Children = parseMP4Atoms(data, pos+childHeader, pos+size, depth+1)
		}

		atoms = append(atoms, atom)
		pos += size
	}

	return atoms
}

func detectMP4Threats(data []byte, atoms []MP4Atom) []MP4Threat {
	var threats []MP4Threat

	// Check for multiple video tracks (possible hidden content)
	trackCount := 0
	for _, atom := range atoms {
		if atom.Type == "moov" {
			for _, child := range atom.Children {
				if child.Type == "trak" {
					trackCount++
				}
			}
		}
	}
	if trackCount > 2 {
		threats = append(threats, MP4Threat{
			Type:       "hidden_track",
			Confidence: 0.5,
			Evidence:   "Multiple video tracks detected — possible hidden content",
		})
	}

	// Check for encrypted atoms
	for _, atom := range atoms {
		if atom.Type == "tenc" || atom.Type == "senc" {
			threats = append(threats, MP4Threat{
				Type:       "encrypted",
				Confidence: 0.4,
				Evidence:   "Encrypted segment detected: " + atom.Type,
			})
		}
	}

	// Check for unusual atom sizes
	totalSize := len(data)
	for _, atom := range atoms {
		if atom.Size > totalSize/2 && atom.Type != "mdat" && atom.Type != "moov" {
			threats = append(threats, MP4Threat{
				Type:       "unusual_atom_size",
				Confidence: 0.3,
				Evidence:   "Unusually large atom: " + atom.Type,
			})
		}
	}

	return threats
}
