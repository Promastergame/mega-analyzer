package media3d

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// glTF JSON DOCUMENT
//
// A deliberately lenient view of the JSON chunk. Every array the core spec
// defines is decoded as json.RawMessage unless this package actually reads
// inside it, so an unknown or future field can never fail the parse. Only the
// arrays we count into (meshes, accessors, buffers, images) get real structs.
// ═══════════════════════════════════════════════════════════════════════════════

// Primitive rendering modes from the core spec. Counting triangles without
// consulting the mode is the single most common way to get a face count wrong:
// a strip of N indices is N-2 triangles, not N/3.
const (
	modePoints = iota
	modeLines
	modeLineLoop
	modeLineStrip
	modeTriangles
	modeTriangleStrip
	modeTriangleFan
)

// Counts is the per-array census of a glTF document.
type Counts struct {
	Scenes      int
	Nodes       int
	Meshes      int
	Primitives  int
	Materials   int
	Textures    int
	Images      int
	Samplers    int
	Accessors   int
	BufferViews int
	Buffers     int
	Animations  int
	Skins       int
	Cameras     int
}

type gltfBuffer struct {
	ByteLength int    `json:"byteLength"`
	URI        string `json:"uri"`
}

type gltfImage struct {
	URI        string `json:"uri"`
	MimeType   string `json:"mimeType"`
	BufferView *int   `json:"bufferView"`
	Extensions map[string]json.RawMessage `json:"extensions"`
}

type gltfAccessor struct {
	Count         int    `json:"count"`
	Type          string `json:"type"`
	ComponentType int    `json:"componentType"`
}

type gltfPrimitive struct {
	Attributes map[string]int             `json:"attributes"`
	Indices    *int                       `json:"indices"`
	Mode       *int                       `json:"mode"`
	Extensions map[string]json.RawMessage `json:"extensions"`
}

type gltfMesh struct {
	Primitives []gltfPrimitive `json:"primitives"`
}

type gltfAsset struct {
	Version    string `json:"version"`
	MinVersion string `json:"minVersion"`
	Generator  string `json:"generator"`
	Copyright  string `json:"copyright"`
}

// Document is the parsed JSON chunk.
type Document struct {
	Asset              gltfAsset `json:"asset"`
	ExtensionsUsed     []string  `json:"extensionsUsed"`
	ExtensionsRequired []string  `json:"extensionsRequired"`

	Scenes      []json.RawMessage `json:"scenes"`
	Nodes       []json.RawMessage `json:"nodes"`
	Meshes      []gltfMesh        `json:"meshes"`
	Materials   []json.RawMessage `json:"materials"`
	Textures    []json.RawMessage `json:"textures"`
	Images      []gltfImage       `json:"images"`
	Samplers    []json.RawMessage `json:"samplers"`
	Accessors   []gltfAccessor    `json:"accessors"`
	BufferViews []json.RawMessage `json:"bufferViews"`
	Buffers     []gltfBuffer      `json:"buffers"`
	Animations  []json.RawMessage `json:"animations"`
	Skins       []json.RawMessage `json:"skins"`
	Cameras     []json.RawMessage `json:"cameras"`
}

// trimChunkPadding removes the padding a GLB producer appends to reach a
// 4-byte boundary. The spec says pad the JSON chunk with spaces, but NUL
// padding is common in the wild and encoding/json rejects it, which turns a
// perfectly readable asset into a parse failure.
func trimChunkPadding(b []byte) []byte {
	return bytes.TrimRight(b, "\x00 \t\r\n")
}

// ParseDocument decodes a glTF JSON payload, tolerating GLB chunk padding and
// a UTF-8 BOM.
func ParseDocument(b []byte) (*Document, error) {
	b = trimChunkPadding(b)
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	b = bytes.TrimLeft(b, " \t\r\n")

	var doc Document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Counts returns the per-array census.
func (d *Document) Counts() Counts {
	c := Counts{
		Scenes:      len(d.Scenes),
		Nodes:       len(d.Nodes),
		Meshes:      len(d.Meshes),
		Materials:   len(d.Materials),
		Textures:    len(d.Textures),
		Images:      len(d.Images),
		Samplers:    len(d.Samplers),
		Accessors:   len(d.Accessors),
		BufferViews: len(d.BufferViews),
		Buffers:     len(d.Buffers),
		Animations:  len(d.Animations),
		Skins:       len(d.Skins),
		Cameras:     len(d.Cameras),
	}
	for i := range d.Meshes {
		c.Primitives += len(d.Meshes[i].Primitives)
	}
	return c
}

// Geometry sums vertices and faces across every primitive.
//
// compressed is set when at least one primitive carries a geometry-compression
// extension. In that case the accessor counts describe the mesh after decode,
// so the numbers stay meaningful while the underlying buffer bytes are not
// vertex data at all - a distinction worth reporting rather than hiding.
func (d *Document) Geometry() (vertices, faces int, compressed bool) {
	for mi := range d.Meshes {
		for pi := range d.Meshes[mi].Primitives {
			p := &d.Meshes[mi].Primitives[pi]

			for name := range p.Extensions {
				if info, ok := extensionRegistry[name]; ok && info.Class == ExtGeometryCompression {
					compressed = true
				}
			}

			if idx, ok := p.Attributes["POSITION"]; ok {
				if idx >= 0 && idx < len(d.Accessors) {
					vertices += d.Accessors[idx].Count
				}
			}

			mode := modeTriangles
			if p.Mode != nil {
				mode = *p.Mode
			}

			// Element count comes from the index accessor when indexed, and
			// from POSITION otherwise: a non-indexed primitive still draws.
			n := 0
			if p.Indices != nil && *p.Indices >= 0 && *p.Indices < len(d.Accessors) {
				n = d.Accessors[*p.Indices].Count
			} else if idx, ok := p.Attributes["POSITION"]; ok && idx >= 0 && idx < len(d.Accessors) {
				n = d.Accessors[idx].Count
			}

			switch mode {
			case modeTriangles:
				faces += n / 3
			case modeTriangleStrip, modeTriangleFan:
				if n >= 3 {
					faces += n - 2
				}
				// points, lines, line loop and line strip contribute no faces.
			}
		}
	}
	return vertices, faces, compressed
}

// ExternalResources lists buffer and image URIs that point outside the file.
// Data URIs are self-contained and GLB-internal buffers have no URI at all, so
// anything left is a dependency the asset cannot satisfy on its own - and, for
// an artifact pulled out of an APK, a path worth reading.
func (d *Document) ExternalResources() []string {
	var out []string
	seen := make(map[string]bool)

	add := func(uri string) {
		if uri == "" || strings.HasPrefix(uri, "data:") || seen[uri] {
			return
		}
		seen[uri] = true
		out = append(out, uri)
	}
	for i := range d.Buffers {
		add(d.Buffers[i].URI)
	}
	for i := range d.Images {
		add(d.Images[i].URI)
	}
	return out
}

// ImageMimeTypes lists the distinct mimeType values declared on images, in
// first-seen order.
func (d *Document) ImageMimeTypes() []string {
	var out []string
	seen := make(map[string]bool)
	for i := range d.Images {
		m := d.Images[i].MimeType
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// parseVersion splits a "major.minor" asset version. ok is false when the
// string is not in that shape, which is itself a spec violation worth
// surfacing rather than silently treating as 0.0.
func parseVersion(s string) (major, minor int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	majStr, minStr, found := strings.Cut(s, ".")
	if !found {
		minStr = "0"
	}
	maj, err := strconv.Atoi(strings.TrimSpace(majStr))
	if err != nil {
		return 0, 0, false
	}
	// A patch component is not part of the asset version grammar, but tolerate
	// "2.0.1" rather than rejecting the whole document over it.
	if i := strings.IndexByte(minStr, '.'); i >= 0 {
		minStr = minStr[:i]
	}
	mn, err := strconv.Atoi(strings.TrimSpace(minStr))
	if err != nil {
		return maj, 0, true
	}
	return maj, mn, true
}
