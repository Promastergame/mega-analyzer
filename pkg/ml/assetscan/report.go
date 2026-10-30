package assetscan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT SHAPE
//
// One struct set serves three consumers: the terminal renderer below, the JSON
// the Zig editor parses, and any Go caller embedding the scanner. Every field
// is exported with an explicit json tag so the wire format is a deliberate
// contract rather than an accident of Go naming.
// ═══════════════════════════════════════════════════════════════════════════════

// Item classes.
const (
	ClassThreeD    = "3d"
	ClassImage     = "image"
	ClassTexture   = "texture"
	ClassEncrypted = "encrypted"
	ClassPacked    = "packed"
	ClassOther     = "other"
)

// ClassOrder is the display order used by the renderer and the summary line.
var ClassOrder = []string{ClassThreeD, ClassTexture, ClassImage, ClassEncrypted, ClassPacked, ClassOther}

// ThreeDInfo is the glTF verdict for one asset.
type ThreeDInfo struct {
	Kind               string   `json:"kind"`
	AssetVersion       string   `json:"assetVersion,omitempty"`
	Generator          string   `json:"generator,omitempty"`
	Vertices           int      `json:"vertices"`
	Faces              int      `json:"faces"`
	Compressed         bool     `json:"compressed"`
	VendorChunks       []string `json:"vendorChunks,omitempty"`
	ExtensionsRequired []string `json:"extensionsRequired,omitempty"`
	Unrecognized       []string `json:"unrecognized,omitempty"`
	StockLoadable      bool     `json:"stockLoadable"`
	Blockers           []string `json:"blockers,omitempty"`
	Anomalies          []string `json:"anomalies,omitempty"`
	Textures           int      `json:"textures"`

	// UVSets is how many TEXCOORD_n sets the materials require. A mesh that
	// only supplies UV0 renders every higher set wrong, which is one of the
	// commonest reasons a ripped model looks almost right.
	UVSets int `json:"uvSets,omitempty"`
	// UnboundImages lists images no material references: dead weight, or a
	// sign the asset was assembled by a tool that left them behind.
	UnboundImages []int `json:"unboundImages,omitempty"`
	// Bindings says where each texture actually lands.
	Bindings []TextureBind `json:"bindings,omitempty"`
}

// TextureBind is one image together with the material slot it fills. This is
// the difference between "this model contains four PNGs" and "this PNG is the
// normal map of the Body material, on UV0, tiled" - which is what you need
// before a texture can be replaced or judged.
type TextureBind struct {
	// Image indexes the model's image list, or -1 when the chain is broken.
	Image int    `json:"image"`
	Slot  string `json:"slot"`
	// Extension names the material extension that owns the slot, empty for
	// the five core PBR slots.
	Extension string `json:"extension,omitempty"`
	Material  string `json:"material"`
	// TexCoord is the UV set the mesh must supply: 0 means TEXCOORD_0.
	TexCoord int `json:"texCoord"`
	// Wrap is the S/T wrap pair, so "repeat/repeat" or "clamp/mirror".
	Wrap string `json:"wrap"`
	// Filter is the min/mag filter pair.
	Filter string `json:"filter,omitempty"`
	// Meshes are the mesh names that draw with this material.
	Meshes []string `json:"meshes,omitempty"`
	// Primitives counts the primitives drawn with this material.
	Primitives int    `json:"primitives"`
	Note       string `json:"note,omitempty"`
}

// FrameInfo is one compressed frame found inside a buffer.
type FrameInfo struct {
	Format       string `json:"format"`
	Offset       int    `json:"offset"`
	DeclaredSize int64  `json:"declaredSize"`
	Decodable    bool   `json:"decodable"`
	Note         string `json:"note,omitempty"`
}

// ImageInfo is the imagedec verdict for one buffer.
type ImageInfo struct {
	// Direct is true when the file already starts with a known signature and
	// needed no transform at all.
	Direct    bool        `json:"direct"`
	Signature string      `json:"signature,omitempty"`
	Family    string      `json:"family,omitempty"`
	Transform string      `json:"transform,omitempty"`
	Base      int         `json:"base"`
	Score     int         `json:"score"`
	Evidence  []string    `json:"evidence,omitempty"`
	Frames    []FrameInfo `json:"frames,omitempty"`
}

// PreviewInfo points at a rendered PNG on disk.
type PreviewInfo struct {
	Path   string `json:"path"`
	Label  string `json:"label"`
	Source string `json:"source"` // file | recovered | texture
	Width  int    `json:"width"`
	Height int    `json:"height"`
	// Decoder is png, jpeg, gif, qoi, bmp, astc or bytemap.
	Decoder string `json:"decoder"`
	// Lossy marks a byte-map visualisation rather than a real decode.
	Lossy bool   `json:"lossy"`
	Note  string `json:"note,omitempty"`
	// Slot names the material slot this texture fills, when the asset says.
	Slot string `json:"slot,omitempty"`
	// Applied is a one-line answer to "how does this lie on the model?".
	Applied string `json:"applied,omitempty"`
}

// ASTCInfo describes a block-compressed texture the scan managed to decode.
//
// A bare ASTC payload has no header at all, so most of this is deduced from
// the block modes rather than read from a field. Certain says which of the two
// happened: true when the byte count could only mean one thing, false when the
// aspect ratio had to be assumed.
type ASTCInfo struct {
	// Footprint is the block size, such as 4x4 or 6x6.
	Footprint string `json:"footprint"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Blocks    int    `json:"blocks"`
	// MipLevels is set only when the payload holds a whole mip pyramid, in
	// which case Width and Height describe level 0 exactly.
	MipLevels int `json:"mipLevels,omitempty"`
	// Certain distinguishes a deduced layout from an assumed one.
	Certain bool `json:"certain"`
	// Illegal counts blocks the decoder had to paint with the error colour.
	// Anything above zero in a real texture means the layout is wrong.
	Illegal int `json:"illegal,omitempty"`
	// VoidExtent counts flat blocks. A large share means a mostly empty
	// atlas, which is worth knowing before hunting for artwork in it.
	VoidExtent int `json:"voidExtent,omitempty"`
	// DualPlane counts blocks carrying a second weight plane, typical of
	// normal maps and of alpha that must not bleed into colour.
	DualPlane int `json:"dualPlane,omitempty"`
	// HDR counts blocks using HDR endpoint modes. This decoder is the LDR
	// profile, so those texels come out as the error colour by design.
	HDR  int    `json:"hdr,omitempty"`
	Note string `json:"note,omitempty"`
}

// Item is one asset found by the scan.
type Item struct {
	Path      string        `json:"path"`
	Container string        `json:"container,omitempty"`
	Size      int64         `json:"size"`
	Class     string        `json:"class"`
	Format    string        `json:"format"`
	Verdict   string        `json:"verdict"`
	ThreeD    *ThreeDInfo   `json:"threeD,omitempty"`
	Image     *ImageInfo    `json:"image,omitempty"`
	ASTC      *ASTCInfo     `json:"astc,omitempty"`
	Previews  []PreviewInfo `json:"previews,omitempty"`
	Notes     []string      `json:"notes,omitempty"`
}

// Display returns the path as the user should read it: prefixed with the
// archive it came out of, if any.
func (i Item) Display() string {
	if i.Container == "" {
		return i.Path
	}
	return i.Container + "!" + i.Path
}

// Report is the whole scan.
type Report struct {
	Target     string         `json:"target"`
	Root       string         `json:"root,omitempty"`
	Scanned    int            `json:"scanned"`
	Matched    int            `json:"matched"`
	Skipped    int            `json:"skipped"`
	PreviewDir string         `json:"previewDir,omitempty"`
	ByClass    map[string]int `json:"byClass"`
	Items      []Item         `json:"items"`
	Errors     []string       `json:"errors,omitempty"`
}

// JSON renders the machine-readable form consumed by the Zig editor.
func (r *Report) JSON() ([]byte, error) {
	// Items must never marshal as null: a JSON consumer written against an
	// array should not have to special-case the empty scan.
	if r.Items == nil {
		r.Items = []Item{}
	}
	if r.ByClass == nil {
		r.ByClass = map[string]int{}
	}
	return json.MarshalIndent(r, "", "  ")
}

// Counts renders the per-class tally in a fixed order.
func (r *Report) Counts() string {
	var parts []string
	for _, c := range ClassOrder {
		if n := r.ByClass[c]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", c, n))
		}
	}
	// Anything the scanner learns to emit later still shows up.
	var extra []string
	for k, n := range r.ByClass {
		known := false
		for _, c := range ClassOrder {
			if c == k {
				known = true
				break
			}
		}
		if !known && n > 0 {
			extra = append(extra, fmt.Sprintf("%s %d", k, n))
		}
	}
	sort.Strings(extra)
	parts = append(parts, extra...)
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, "  ")
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGT"[exp])
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// tail keeps the informative end of a long path.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[len(s)-n:]
	}
	return ".." + s[len(s)-(n-2):]
}

// Text renders the terminal view: one aligned row per asset, then only the
// detail that changes a decision. No banner art, no progress spam - the goal
// is a table you can read at a glance and grep afterwards.
func (r *Report) Text() string {
	var b strings.Builder

	fmt.Fprintf(&b, "asset scan  %s\n", r.Target)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 72))
	fmt.Fprintf(&b, "  %d scanned   %d matched   %d skipped   [%s]\n",
		r.Scanned, r.Matched, r.Skipped, r.Counts())
	if r.PreviewDir != "" {
		fmt.Fprintf(&b, "  previews -> %s\n", r.PreviewDir)
	}
	if len(r.Items) == 0 {
		b.WriteString("\n  no 3D, image or encrypted assets found\n")
		return b.String()
	}
	b.WriteString("\n")

	nameW := 8
	for i := range r.Items {
		if n := len(tail(r.Items[i].Display(), 52)); n > nameW {
			nameW = n
		}
	}

	for i := range r.Items {
		it := &r.Items[i]
		fmt.Fprintf(&b, "  %s  %s  %s  %s\n",
			pad(it.Class, 9),
			pad(tail(it.Display(), 52), nameW),
			pad(humanSize(it.Size), 7),
			it.Verdict)

		if d := it.ThreeD; d != nil && !d.StockLoadable {
			for _, blk := range d.Blockers {
				fmt.Fprintf(&b, "  %s  blocker: %s\n", pad("", 9), blk)
			}
		}
		if im := it.Image; im != nil && !im.Direct && im.Transform != "" {
			fmt.Fprintf(&b, "  %s  recovered with %s at +%d (score %d)\n",
				pad("", 9), im.Transform, im.Base, im.Score)
		}
		if im := it.Image; im != nil {
			for _, f := range im.Frames {
				size := "unknown size"
				if f.DeclaredSize >= 0 {
					size = humanSize(f.DeclaredSize)
				}
				fmt.Fprintf(&b, "  %s  %s frame at +%d, %s%s\n",
					pad("", 9), f.Format, f.Offset, size,
					map[bool]string{true: "", false: " (header only)"}[f.Decodable])
			}
		}
		for _, p := range it.Previews {
			kind := p.Decoder
			if p.Lossy {
				kind += ", visualisation"
			}
			fmt.Fprintf(&b, "  %s  png %dx%d %s -> %s\n",
				pad("", 9), p.Width, p.Height, kind, p.Path)
		}
		for _, n := range it.Notes {
			fmt.Fprintf(&b, "  %s  note: %s\n", pad("", 9), n)
		}
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "\n  %d entr%s could not be read:\n", len(r.Errors),
			map[bool]string{true: "y", false: "ies"}[len(r.Errors) == 1])
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "    %s\n", e)
		}
	}
	return b.String()
}
