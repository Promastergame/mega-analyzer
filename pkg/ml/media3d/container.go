package media3d

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// GLB CONTAINER READER
//
// The GLB container is deliberately open-ended. Khronos fixes a 12-byte header
// and then says "one or more chunks", with unknown chunk types reserved for
// extensions and explicitly required to be skippable by a conforming loader.
//
// That freedom is used in the wild. Supercell ships Brawl Stars models as a GLB
// whose first chunk is "FLA2" (a FlatBuffers scene) instead of "JSON". glTF 1.0
// used a different header shape again: KHR_binary_glTF put contentLength and
// contentFormat at offsets 12 and 16, so the chunk table does not start where a
// 2.0 reader expects it.
//
// This reader therefore never assumes a layout. It walks whatever is present,
// records every deviation as an anomaly instead of failing, and lets the caller
// decide what the file is. Two invariants hold throughout:
//
//	1. No length taken from the file is ever used to size an allocation.
//	   Chunk payloads are sub-slices of the caller's buffer, never copies.
//	2. Every loop advances by a positive constant, so a hostile chunk table
//	   cannot spin.
// ═══════════════════════════════════════════════════════════════════════════════

// Magic is the little-endian uint32 spelling of the ASCII tag "glTF".
const Magic uint32 = 0x46546C67

const (
	headerSize     = 12
	chunkHeadSize  = 8
	legacyHeadSize = 20 // glTF 1.0 adds contentLength + contentFormat

	// maxChunks bounds the walk. A real asset has two or three chunks; a file
	// that produces thousands is a fuzz case or a misparse, and continuing
	// only grows the anomaly list.
	maxChunks = 4096
)

// Errors returned by ReadContainer. Everything else is reported as an anomaly
// on the returned Container rather than as an error, because a container that
// deviates from the spec is exactly what this package exists to describe.
var (
	ErrShortHeader = errors.New("media3d: buffer is shorter than the 12-byte GLB header")
	ErrNotGLB      = errors.New("media3d: missing glTF magic")
)

// ChunkKind is the role a chunk plays, derived from its 4-byte tag.
type ChunkKind uint8

const (
	// KindUnknown is a tag that is neither JSON nor BIN nor printable ASCII.
	KindUnknown ChunkKind = iota
	// KindJSON is the structured content chunk the spec requires first.
	KindJSON
	// KindBIN is the binary buffer chunk.
	KindBIN
	// KindVendor is a printable-ASCII tag that is not JSON or BIN: a
	// deliberate extension chunk such as Supercell's FLA2.
	KindVendor
)

func (k ChunkKind) String() string {
	switch k {
	case KindJSON:
		return "json"
	case KindBIN:
		return "bin"
	case KindVendor:
		return "vendor"
	default:
		return "unknown"
	}
}

// Chunk is one entry of the GLB chunk table.
type Chunk struct {
	// RawTag is the tag exactly as stored, including any NUL padding.
	RawTag [4]byte
	// Tag is RawTag with non-printable bytes rendered as '.' so it is safe to
	// put in a report or a log line.
	Tag  string
	Kind ChunkKind
	// Offset is where chunkData begins in the original buffer.
	Offset int
	// Length is the declared chunkLength, which may exceed len(Data).
	Length int
	// Data is a sub-slice of the caller's buffer. Never a copy.
	Data []byte
	// Aligned records whether chunkData started on a 4-byte boundary.
	Aligned bool
	// Truncated is set when the declared length ran past the end of the
	// buffer; Data then holds only the bytes that actually exist.
	Truncated bool
}

// Container is a parsed GLB chunk table plus everything that was wrong with it.
type Container struct {
	// Version is the container version from the header, not the asset version.
	// The spec is explicit that these are different numbers and that a loader
	// must check asset.version in the JSON chunk as well.
	Version uint32
	// Declared is the total length claimed by the header.
	Declared uint32
	// Actual is len(data) as supplied.
	Actual int
	// Legacy marks a glTF 1.0 KHR_binary_glTF container.
	Legacy bool

	Chunks    []Chunk
	Anomalies []string
}

func (c *Container) note(format string, args ...any) {
	c.Anomalies = append(c.Anomalies, fmt.Sprintf(format, args...))
}

// normTag drops the NUL and space padding producers use to fill a 4-byte tag,
// so that Find("BIN") matches the stored "BIN\x00".
func normTag(b []byte) string {
	return strings.TrimRight(string(b), "\x00 ")
}

func printableTag(b [4]byte) string {
	out := make([]byte, 4)
	for i, v := range b {
		if v >= 0x20 && v < 0x7f {
			out[i] = v
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func classifyTag(raw [4]byte) ChunkKind {
	switch normTag(raw[:]) {
	case "JSON":
		return KindJSON
	case "BIN":
		return KindBIN
	case "":
		// An all-NUL tag is padding or corruption, not a vendor chunk.
		return KindUnknown
	}
	for _, v := range raw {
		if v != 0 && (v < 0x20 || v >= 0x7f) {
			return KindUnknown
		}
	}
	return KindVendor
}

// Find returns the payload of the first chunk whose tag matches, ignoring NUL
// and space padding on either side. Find("BIN") and Find("BIN\x00") are the
// same query.
func (c *Container) Find(tag string) ([]byte, bool) {
	want := strings.TrimRight(tag, "\x00 ")
	for i := range c.Chunks {
		if normTag(c.Chunks[i].RawTag[:]) == want {
			return c.Chunks[i].Data, true
		}
	}
	return nil, false
}

// JSON returns the payload of the first JSON chunk.
func (c *Container) JSON() ([]byte, bool) {
	for i := range c.Chunks {
		if c.Chunks[i].Kind == KindJSON {
			return c.Chunks[i].Data, true
		}
	}
	return nil, false
}

// VendorTags lists the printable tags that are neither JSON nor BIN. These are
// the chunks a stock loader will skip, and the reason a file can be a valid
// GLB container while carrying a scene no glTF loader understands.
func (c *Container) VendorTags() []string {
	var out []string
	for i := range c.Chunks {
		if c.Chunks[i].Kind == KindVendor {
			out = append(out, normTag(c.Chunks[i].RawTag[:]))
		}
	}
	return out
}

// IsGLB reports whether the buffer opens with the GLB header magic.
func IsGLB(data []byte) bool {
	return len(data) >= headerSize && binary.LittleEndian.Uint32(data[0:4]) == Magic
}

// ReadContainer walks a GLB chunk table. It fails only when the buffer cannot
// be a GLB at all; every other deviation lands in Container.Anomalies.
func ReadContainer(data []byte) (*Container, error) {
	if len(data) < headerSize {
		return nil, ErrShortHeader
	}
	if binary.LittleEndian.Uint32(data[0:4]) != Magic {
		return nil, ErrNotGLB
	}

	c := &Container{
		Version:  binary.LittleEndian.Uint32(data[4:8]),
		Declared: binary.LittleEndian.Uint32(data[8:12]),
		Actual:   len(data),
	}

	switch {
	case uint64(c.Declared) > uint64(len(data)):
		c.note("header declares %d bytes but only %d are present: truncated transfer or a split asset",
			c.Declared, len(data))
	case uint64(c.Declared) < uint64(len(data)):
		c.note("header declares %d bytes but %d are present: %d trailing bytes sit past the container",
			c.Declared, len(data), len(data)-int(c.Declared))
	}

	if c.Version == 1 {
		c.Legacy = true
		c.note("container version 1: this is the glTF 1.0 KHR_binary_glTF layout, " +
			"whose header is 20 bytes and which has no chunk table")
		readLegacy(c, data)
		return c, nil
	}
	if c.Version != 2 {
		c.note("container version %d is outside the range the specification defines (1 and 2)", c.Version)
	}

	readChunks(c, data)
	return c, nil
}

func readChunks(c *Container, data []byte) {
	off := headerSize
	for off+chunkHeadSize <= len(data) {
		if len(c.Chunks) >= maxChunks {
			c.note("stopped after %d chunks: the chunk table does not terminate", maxChunks)
			return
		}

		// uint64 throughout: chunkLength is a full uint32 and int is 32 bits on
		// GOARCH=arm and 386, where start+clen would otherwise wrap negative.
		clen := uint64(binary.LittleEndian.Uint32(data[off : off+4]))
		var raw [4]byte
		copy(raw[:], data[off+4:off+8])

		start := off + chunkHeadSize
		end := uint64(start) + clen
		truncated := false
		if end > uint64(len(data)) {
			truncated = true
			end = uint64(len(data))
		}

		ch := Chunk{
			RawTag:    raw,
			Tag:       printableTag(raw),
			Kind:      classifyTag(raw),
			Offset:    start,
			Length:    int(clen),
			Data:      data[start:int(end)],
			Aligned:   start%4 == 0,
			Truncated: truncated,
		}
		c.Chunks = append(c.Chunks, ch)

		if truncated {
			c.note("chunk %q at offset %d declares %d bytes but only %d remain",
				ch.Tag, start, clen, len(data)-start)
			return
		}
		if clen%4 != 0 {
			c.note("chunk %q length %d is not a multiple of 4; the spec requires chunks to be padded to a 4-byte boundary",
				ch.Tag, clen)
		}
		if ch.Kind == KindUnknown {
			c.note("chunk %d has a non-printable tag % x, which no extension can legitimately register",
				len(c.Chunks)-1, raw[:])
		}

		off = int(end)
	}

	if off < len(data) {
		c.note("%d trailing bytes after the last complete chunk header", len(data)-off)
	}
}

// readLegacy handles the glTF 1.0 KHR_binary_glTF layout, where the 12-byte
// header is followed by contentLength and contentFormat rather than by a chunk
// table. Reading such a file with a 2.0 walker produces nonsense chunk tags,
// which is why the version is checked before the walk rather than after.
func readLegacy(c *Container, data []byte) {
	if len(data) < legacyHeadSize {
		c.note("version 1 container is shorter than its 20-byte header")
		return
	}

	contentLen := uint64(binary.LittleEndian.Uint32(data[12:16]))
	contentFmt := binary.LittleEndian.Uint32(data[16:20])
	if contentFmt != 0 {
		c.note("version 1 contentFormat is %d; the extension defines only 0 (JSON)", contentFmt)
	}

	start := legacyHeadSize
	end := uint64(start) + contentLen
	truncated := false
	if end > uint64(len(data)) {
		truncated = true
		end = uint64(len(data))
		c.note("version 1 contentLength %d runs past the end of the buffer", contentLen)
	}

	c.Chunks = append(c.Chunks, Chunk{
		RawTag:    [4]byte{'J', 'S', 'O', 'N'},
		Tag:       "JSON",
		Kind:      KindJSON,
		Offset:    start,
		Length:    int(contentLen),
		Data:      data[start:int(end)],
		Aligned:   start%4 == 0,
		Truncated: truncated,
	})

	if body := int(end); !truncated && body < len(data) {
		c.Chunks = append(c.Chunks, Chunk{
			RawTag:  [4]byte{'B', 'I', 'N', 0},
			Tag:     "BIN.",
			Kind:    KindBIN,
			Offset:  body,
			Length:  len(data) - body,
			Data:    data[body:],
			Aligned: body%4 == 0,
		})
	}
}
