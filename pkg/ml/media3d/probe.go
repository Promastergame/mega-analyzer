package media3d

import (
	"bytes"
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROBE - the single entry point
//
// Probe answers one question that matters more than any metric: will a stock
// glTF 2.0 loader open this file, and if not, exactly why not.
//
// That framing is deliberate. A vendor GLB can be a structurally perfect
// container and still be unopenable in Blender or three.js, because the spec
// requires the FIRST chunk to be JSON. Reporting "0 vertices" for such a file
// is useless; reporting "first chunk is FLA2, not JSON" is actionable.
// ═══════════════════════════════════════════════════════════════════════════════

// ChunkSummary is the reportable projection of a Chunk, without the payload.
type ChunkSummary struct {
	Tag       string
	Kind      string
	Offset    int
	Length    int
	Aligned   bool
	Truncated bool
}

// Report is everything Probe could establish about a 3D asset.
type Report struct {
	// Kind is "glb", "glb1" (the glTF 1.0 container) or "gltf" (bare JSON).
	Kind        string
	Version     uint32
	DeclaredLen uint32
	ActualLen   int

	Chunks       []ChunkSummary
	HasJSON      bool
	VendorChunks []string

	AssetVersion string
	MinVersion   string
	Generator    string

	ExtensionsUsed     []string
	ExtensionsRequired []string
	// Unrecognized are extension names absent from the registry. When one of
	// these also appears in extensionsRequired the asset is unloadable here.
	Unrecognized []string

	GeometryCompression []string
	TextureCodecs       []string
	ImageMimeTypes      []string
	ExternalResources   []string

	Counts     Counts
	Vertices   int
	Faces      int
	Compressed bool

	// StockLoadable is the verdict: can an unmodified glTF 2.0 loader open it.
	StockLoadable bool
	// Blockers are the specific reasons StockLoadable is false.
	Blockers []string
	// Anomalies are deviations that do not by themselves stop a loader.
	Anomalies []string
}

// Summary renders a one-line human-readable verdict.
func (r Report) Summary() string {
	if r.Kind == "" {
		return "not a glTF asset"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s", r.Kind)
	if r.AssetVersion != "" {
		fmt.Fprintf(&b, " asset %s", r.AssetVersion)
	}
	fmt.Fprintf(&b, ", %d verts, %d faces", r.Vertices, r.Faces)
	if len(r.VendorChunks) > 0 {
		fmt.Fprintf(&b, ", vendor chunks %s", strings.Join(r.VendorChunks, "+"))
	}
	if r.StockLoadable {
		b.WriteString(", loads in a stock glTF 2.0 viewer")
	} else {
		fmt.Fprintf(&b, ", NOT stock-loadable (%d blocker(s))", len(r.Blockers))
	}
	return b.String()
}

func (r *Report) block(format string, args ...any) {
	r.Blockers = append(r.Blockers, fmt.Sprintf(format, args...))
}

// looksLikeJSON reports whether the buffer opens with a JSON object once a BOM
// and leading whitespace are skipped.
func looksLikeJSON(data []byte) bool {
	b := bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && b[0] == '{'
}

// Probe inspects a buffer that is expected to be a glTF asset in either
// packaging. It never returns an error: an unrecognized buffer produces a
// Report with an empty Kind.
func Probe(data []byte) Report {
	var r Report
	r.ActualLen = len(data)

	switch {
	case IsGLB(data):
		probeContainer(&r, data)
	case looksLikeJSON(data):
		r.Kind = "gltf"
		probeJSON(&r, data, true)
	default:
		return r
	}
	return r
}

func probeContainer(r *Report, data []byte) {
	c, err := ReadContainer(data)
	if err != nil {
		return
	}

	r.Kind = "glb"
	if c.Legacy {
		r.Kind = "glb1"
	}
	r.Version = c.Version
	r.DeclaredLen = c.Declared
	r.Anomalies = append(r.Anomalies, c.Anomalies...)
	r.VendorChunks = c.VendorTags()

	for i := range c.Chunks {
		ch := &c.Chunks[i]
		r.Chunks = append(r.Chunks, ChunkSummary{
			Tag:       ch.Tag,
			Kind:      ch.Kind.String(),
			Offset:    ch.Offset,
			Length:    ch.Length,
			Aligned:   ch.Aligned,
			Truncated: ch.Truncated,
		})
	}

	// The spec is unambiguous: the first chunk MUST be the JSON content. A
	// vendor chunk in that slot is the whole reason a Supercell .glb opens in
	// a hex editor as "a normal glTF" and then fails in every viewer.
	if len(c.Chunks) == 0 {
		r.block("container has no chunks at all")
	} else if c.Chunks[0].Kind != KindJSON {
		r.block("first chunk is %q (%s), but the specification requires the JSON chunk to come first",
			c.Chunks[0].Tag, c.Chunks[0].Kind)
	}
	if c.Legacy {
		r.block("glTF 1.0 container: a 2.0-only loader will not read the 20-byte KHR_binary_glTF header")
	}
	for i := range c.Chunks {
		if c.Chunks[i].Truncated {
			r.block("chunk %q is truncated", c.Chunks[i].Tag)
		}
	}

	jsonChunk, ok := c.JSON()
	r.HasJSON = ok
	if !ok {
		r.block("no JSON chunk: there is no glTF document in this container")
		r.StockLoadable = false
		return
	}
	probeJSON(r, jsonChunk, false)
}

func probeJSON(r *Report, payload []byte, standalone bool) {
	doc, err := ParseDocument(payload)
	if err != nil {
		r.block("JSON content does not parse: %v", err)
		r.StockLoadable = false
		return
	}
	r.HasJSON = true

	r.AssetVersion = doc.Asset.Version
	r.MinVersion = doc.Asset.MinVersion
	r.Generator = doc.Asset.Generator
	r.ExtensionsUsed = doc.ExtensionsUsed
	r.ExtensionsRequired = doc.ExtensionsRequired
	r.Counts = doc.Counts()
	r.Vertices, r.Faces, r.Compressed = doc.Geometry()
	r.ImageMimeTypes = doc.ImageMimeTypes()
	r.ExternalResources = doc.ExternalResources()

	// asset.version is the only strictly required member of the whole document.
	switch major, _, parsed := parseVersion(doc.Asset.Version); {
	case doc.Asset.Version == "":
		r.block("asset.version is missing; it is the one member the core spec makes mandatory")
	case !parsed:
		r.block("asset.version %q is not in major.minor form", doc.Asset.Version)
	case major != 2:
		r.block("asset.version %q is not a 2.x document", doc.Asset.Version)
	}

	// minVersion is the producer telling loaders the floor they must meet.
	if doc.Asset.MinVersion != "" {
		if major, minor, parsed := parseVersion(doc.Asset.MinVersion); !parsed {
			r.block("asset.minVersion %q is not in major.minor form", doc.Asset.MinVersion)
		} else if major > 2 || (major == 2 && minor > 0) {
			r.block("asset.minVersion %q is above 2.0, so a baseline 2.0 loader must refuse the file",
				doc.Asset.MinVersion)
		}
	}

	allNames := append(append([]string{}, doc.ExtensionsUsed...), doc.ExtensionsRequired...)
	known, unknown := classifyExtensions(allNames)
	r.Unrecognized = unknown

	seenComp := make(map[string]bool)
	seenCodec := make(map[string]bool)
	for _, info := range known {
		switch info.Class {
		case ExtGeometryCompression:
			if !seenComp[info.Name] {
				seenComp[info.Name] = true
				r.GeometryCompression = append(r.GeometryCompression, info.Name)
			}
		case ExtTextureCodec:
			if !seenCodec[info.Name] {
				seenCodec[info.Name] = true
				r.TextureCodecs = append(r.TextureCodecs, info.Name)
			}
		}
		if !info.Ratified {
			r.Anomalies = append(r.Anomalies,
				fmt.Sprintf("extension %s is known but not Khronos-ratified", info.Name))
		}
	}

	// Only a REQUIRED unknown extension is fatal. An unknown optional one is
	// exactly the graceful-degradation path the registry was designed around.
	required := make(map[string]bool, len(doc.ExtensionsRequired))
	for _, n := range doc.ExtensionsRequired {
		required[n] = true
	}
	for _, n := range unknown {
		if required[n] {
			r.block("extensionsRequired names %q, which is not in the registry; a conforming loader must refuse the asset", n)
		} else {
			r.Anomalies = append(r.Anomalies,
				fmt.Sprintf("extension %s is unknown but optional, so it can be ignored", n))
		}
	}

	// extensionsRequired entries are required to also appear in extensionsUsed.
	used := make(map[string]bool, len(doc.ExtensionsUsed))
	for _, n := range doc.ExtensionsUsed {
		used[n] = true
	}
	for _, n := range doc.ExtensionsRequired {
		if !used[n] {
			r.Anomalies = append(r.Anomalies,
				fmt.Sprintf("extension %s is in extensionsRequired but missing from extensionsUsed", n))
		}
	}

	if standalone && len(r.ExternalResources) > 0 {
		r.Anomalies = append(r.Anomalies,
			fmt.Sprintf("%d external resource reference(s); the .gltf cannot render alone",
				len(r.ExternalResources)))
	}

	r.StockLoadable = len(r.Blockers) == 0
}
