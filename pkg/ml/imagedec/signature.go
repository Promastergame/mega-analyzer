package imagedec

import "bytes"

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNATURE TABLE
//
// These entries do double duty. Read forwards they identify a file. Read
// backwards they are KNOWN PLAINTEXT: if a texture has been obfuscated with a
// reversible byte transform, the transform can be solved for directly, because
// we know what the first bytes were SUPPOSED to be.
//
// That is why magic length is recorded honestly and why long magics matter.
// A PNG signature is 8 bytes and a KTX one is 12; against a repeating XOR key
// those give 7 and 11 bytes of verification after the key is recovered, which
// is the difference between a guess and a proof. A 2-byte magic like BMP gives
// none, so it is scored accordingly.
// ═══════════════════════════════════════════════════════════════════════════════

// Family groups a signature by what the payload is.
type Family uint8

const (
	FamilyUnknown Family = iota
	// FamilyRaster is a CPU-side image a decoder can turn into pixels.
	FamilyRaster
	// FamilyGPUTexture is a block-compressed texture meant for upload, not
	// for viewing. This is what mobile games actually ship.
	FamilyGPUTexture
	FamilyVector
	// FamilyCompressed is a generic compression stream. Finding one inside an
	// unknown file is usually the whole game: the real asset is behind it.
	FamilyCompressed
	FamilyContainer
)

func (f Family) String() string {
	switch f {
	case FamilyRaster:
		return "raster"
	case FamilyGPUTexture:
		return "gpu-texture"
	case FamilyVector:
		return "vector"
	case FamilyCompressed:
		return "compressed"
	case FamilyContainer:
		return "container"
	default:
		return "unknown"
	}
}

// Signature is one magic-byte rule.
type Signature struct {
	Name   string
	Ext    string
	Family Family
	// Offset is where Magic must sit.
	Offset int
	Magic  []byte
	// Magic2 at Offset2 is a second fixed run, for formats like RIFF/WEBP and
	// the ISO-BMFF ftyp brands where the first run alone is ambiguous.
	Magic2  []byte
	Offset2 int
	Note    string
}

// Span is the byte index just past the last fixed byte this signature pins.
func (s Signature) Span() int {
	end := s.Offset + len(s.Magic)
	if len(s.Magic2) > 0 && s.Offset2+len(s.Magic2) > end {
		end = s.Offset2 + len(s.Magic2)
	}
	return end
}

// Anchors returns every (offset, byte) pair the signature fixes. This is the
// known-plaintext view used by the recovery solver.
func (s Signature) Anchors() []Anchor {
	out := make([]Anchor, 0, len(s.Magic)+len(s.Magic2))
	for i, b := range s.Magic {
		out = append(out, Anchor{Offset: s.Offset + i, Want: b})
	}
	for i, b := range s.Magic2 {
		out = append(out, Anchor{Offset: s.Offset2 + i, Want: b})
	}
	return out
}

// Anchor is a single known-plaintext constraint: at Offset the plaintext must
// be Want.
type Anchor struct {
	Offset int
	Want   byte
}

// MatchesAt reports whether data satisfies the signature when the payload is
// assumed to start at base.
func (s Signature) MatchesAt(data []byte, base int) bool {
	if base < 0 {
		return false
	}
	if base+s.Span() > len(data) {
		return false
	}
	if !bytes.Equal(data[base+s.Offset:base+s.Offset+len(s.Magic)], s.Magic) {
		return false
	}
	if len(s.Magic2) > 0 {
		if !bytes.Equal(data[base+s.Offset2:base+s.Offset2+len(s.Magic2)], s.Magic2) {
			return false
		}
	}
	return true
}

// signatures is the table. Order is not significant; scoring decides.
var signatures = []Signature{
	// ── raster ───────────────────────────────────────────────────────────
	{Name: "png", Ext: ".png", Family: FamilyRaster,
		Magic: []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		Note:  "8-byte signature, the strongest known plaintext in the table"},
	{Name: "jpeg", Ext: ".jpg", Family: FamilyRaster,
		Magic: []byte{0xFF, 0xD8, 0xFF}},
	{Name: "gif87a", Ext: ".gif", Family: FamilyRaster, Magic: []byte("GIF87a")},
	{Name: "gif89a", Ext: ".gif", Family: FamilyRaster, Magic: []byte("GIF89a")},
	{Name: "bmp", Ext: ".bmp", Family: FamilyRaster, Magic: []byte("BM"),
		Note: "only 2 fixed bytes; never trusted without structural agreement"},
	{Name: "webp", Ext: ".webp", Family: FamilyRaster,
		Magic: []byte("RIFF"), Magic2: []byte("WEBP"), Offset2: 8},
	{Name: "tiff-le", Ext: ".tiff", Family: FamilyRaster, Magic: []byte{'I', 'I', 0x2A, 0x00}},
	{Name: "tiff-be", Ext: ".tiff", Family: FamilyRaster, Magic: []byte{'M', 'M', 0x00, 0x2A}},
	{Name: "qoi", Ext: ".qoi", Family: FamilyRaster, Magic: []byte("qoif")},
	{Name: "ico", Ext: ".ico", Family: FamilyRaster, Magic: []byte{0x00, 0x00, 0x01, 0x00}},
	{Name: "cur", Ext: ".cur", Family: FamilyRaster, Magic: []byte{0x00, 0x00, 0x02, 0x00}},
	{Name: "avif", Ext: ".avif", Family: FamilyRaster,
		Offset: 4, Magic: []byte("ftyp"), Offset2: 8, Magic2: []byte("avif")},
	{Name: "heic", Ext: ".heic", Family: FamilyRaster,
		Offset: 4, Magic: []byte("ftyp"), Offset2: 8, Magic2: []byte("heic")},

	// ── GPU textures: what a mobile game actually ships ──────────────────────
	{Name: "ktx1", Ext: ".ktx", Family: FamilyGPUTexture,
		Magic: []byte{0xAB, 'K', 'T', 'X', ' ', '1', '1', 0xBB, 0x0D, 0x0A, 0x1A, 0x0A},
		Note:  "12-byte signature"},
	{Name: "ktx2", Ext: ".ktx2", Family: FamilyGPUTexture,
		Magic: []byte{0xAB, 'K', 'T', 'X', ' ', '2', '0', 0xBB, 0x0D, 0x0A, 0x1A, 0x0A},
		Note:  "12-byte signature; the container KHR_texture_basisu points at"},
	{Name: "dds", Ext: ".dds", Family: FamilyGPUTexture, Magic: []byte("DDS ")},
	{Name: "pvr3", Ext: ".pvr", Family: FamilyGPUTexture, Magic: []byte{'P', 'V', 'R', 0x03}},
	{Name: "astc", Ext: ".astc", Family: FamilyGPUTexture, Magic: []byte{0x13, 0xAB, 0xA1, 0x5C}},
	{Name: "pkm", Ext: ".pkm", Family: FamilyGPUTexture, Magic: []byte("PKM ")},

	// ── compression streams ────────────────────────────────────────────
	{Name: "zstd", Ext: ".zst", Family: FamilyCompressed, Magic: []byte{0x28, 0xB5, 0x2F, 0xFD}},
	{Name: "gzip", Ext: ".gz", Family: FamilyCompressed, Magic: []byte{0x1F, 0x8B}},
	{Name: "zlib-default", Ext: ".zz", Family: FamilyCompressed, Magic: []byte{0x78, 0x9C}},
	{Name: "zlib-best", Ext: ".zz", Family: FamilyCompressed, Magic: []byte{0x78, 0xDA}},
	{Name: "zlib-none", Ext: ".zz", Family: FamilyCompressed, Magic: []byte{0x78, 0x01}},
	{Name: "bzip2", Ext: ".bz2", Family: FamilyCompressed, Magic: []byte("BZh")},
	{Name: "xz", Ext: ".xz", Family: FamilyCompressed, Magic: []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}},
	{Name: "lz4", Ext: ".lz4", Family: FamilyCompressed, Magic: []byte{0x04, 0x22, 0x4D, 0x18}},
	{Name: "7z", Ext: ".7z", Family: FamilyCompressed, Magic: []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}},

	// ── containers ───────────────────────────────────────────────────
	{Name: "zip", Ext: ".zip", Family: FamilyContainer, Magic: []byte{'P', 'K', 0x03, 0x04}},
	{Name: "glb", Ext: ".glb", Family: FamilyContainer, Magic: []byte("glTF")},
}

// Signatures returns a copy of the table so callers cannot mutate it.
func Signatures() []Signature {
	out := make([]Signature, len(signatures))
	copy(out, signatures)
	return out
}

// SignatureCount reports the table size. Tests assert against it so an
// accidentally emptied table cannot pass silently.
func SignatureCount() int { return len(signatures) }

// Identify returns the first signature that matches at the given base offset.
func Identify(data []byte, base int) (Signature, bool) {
	best := Signature{}
	found := false
	for _, s := range signatures {
		if !s.MatchesAt(data, base) {
			continue
		}
		// Prefer the signature that pins the most bytes, so "ktx2" wins over a
		// hypothetical shorter prefix and "webp" wins over a bare "RIFF".
		if !found || s.Span() > best.Span() {
			best, found = s, true
		}
	}
	return best, found
}
