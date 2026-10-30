package astc

import (
	"encoding/binary"
	"fmt"
)

// ── Containers ──────────────────────────────────────────────────────────
//
// A raw ASTC payload carries no dimensions - the blocks alone do not say how
// wide the texture is, and a decoder cannot guess. Two wrappers supply that,
// and both turn up in shipped assets:
//
//   .astc  the reference encoder's own 16-byte header. Ugly, undocumented
//          outside the tool, and everywhere.
//   KTX2   the Khronos container, which names the format through a Vulkan
//          format enum and can compress each mip level with zstd. A .sctx is
//          the same trick with a FlatBuffers head instead.
//
// Both are parsed here so that the caller never has to hand-roll a header.

// FileMagic is the little-endian .astc magic, 0x5CA1AB13 - "scalable", if you
// squint at it the way the reference encoder's authors did.
var FileMagic = [4]byte{0x13, 0xAB, 0xA1, 0x5C}

// FileHeaderSize is the size of the .astc header in bytes.
const FileHeaderSize = 16

// FileHeader is a parsed .astc header.
type FileHeader struct {
	Footprint Footprint
	// BlockDepth is 1 for every 2D texture. A larger value means a 3D
	// footprint, which this decoder does not handle.
	BlockDepth int
	Width      int
	Height     int
	Depth      int
	// DataOffset is where the block payload starts.
	DataOffset int
}

// IsFile reports whether data starts with the .astc magic.
func IsFile(data []byte) bool {
	return len(data) >= 4 && data[0] == FileMagic[0] && data[1] == FileMagic[1] &&
		data[2] == FileMagic[2] && data[3] == FileMagic[3]
}

// ParseFileHeader reads a .astc header.
func ParseFileHeader(data []byte) (FileHeader, error) {
	var h FileHeader
	if len(data) < FileHeaderSize {
		return h, ErrHeader
	}
	if !IsFile(data) {
		return h, ErrMagic
	}
	u24 := func(at int) int {
		return int(data[at]) | (int(data[at+1]) << 8) | (int(data[at+2]) << 16)
	}
	h.Footprint = Footprint{Width: int(data[4]), Height: int(data[5])}
	h.BlockDepth = int(data[6])
	h.Width = u24(7)
	h.Height = u24(10)
	h.Depth = u24(13)
	h.DataOffset = FileHeaderSize
	if h.BlockDepth != 1 {
		return h, fmt.Errorf("%w: 3D footprint %dx%dx%d is not supported",
			ErrFootprint, h.Footprint.Width, h.Footprint.Height, h.BlockDepth)
	}
	if !ValidFootprint(h.Footprint.Width, h.Footprint.Height) {
		return h, fmt.Errorf("%w: %s", ErrFootprint, h.Footprint)
	}
	if h.Width <= 0 || h.Height <= 0 || h.Width > maxSide || h.Height > maxSide {
		return h, ErrDims
	}
	return h, nil
}

// DecodeFile decodes a complete .astc file, mip level 0 only - the format
// stores exactly one level.
func DecodeFile(data []byte, srgb bool) (*Image, Stats, error) {
	h, err := ParseFileHeader(data)
	if err != nil {
		return nil, Stats{}, err
	}
	return DecodeWithStats(data[h.DataOffset:], h.Width, h.Height, h.Footprint, srgb)
}

// ── Format enums ─────────────────────────────────────────────────────
//
// Vulkan and OpenGL both enumerate the fourteen LDR footprints in the same
// order, each as a linear/sRGB pair, so one ordered table serves both. Note
// that this order is not the bit-rate order Footprints() returns: 8x8 sits
// between 8x6 and 10x5 here.

var enumOrder = [14]Footprint{
	{4, 4}, {5, 4}, {5, 5}, {6, 5}, {6, 6}, {8, 5}, {8, 6}, {8, 8},
	{10, 5}, {10, 6}, {10, 8}, {10, 10}, {12, 10}, {12, 12},
}

const (
	vkASTC4x4UnormBlock = 157
	glASTC4x4           = 0x93B0
	glASTCSRGB4x4       = 0x93D0
)

// FootprintForVkFormat maps a Vulkan format enum to a footprint. The second
// result is whether the format is sRGB.
func FootprintForVkFormat(vk uint32) (Footprint, bool, bool) {
	if vk < vkASTC4x4UnormBlock || vk > vkASTC4x4UnormBlock+27 {
		return Footprint{}, false, false
	}
	idx := int(vk-vkASTC4x4UnormBlock) / 2
	srgb := (vk-vkASTC4x4UnormBlock)%2 == 1
	return enumOrder[idx], srgb, true
}

// FootprintForGLFormat maps an OpenGL internal format to a footprint.
func FootprintForGLFormat(gl uint32) (Footprint, bool, bool) {
	if gl >= glASTC4x4 && gl <= glASTC4x4+13 {
		return enumOrder[gl-glASTC4x4], false, true
	}
	if gl >= glASTCSRGB4x4 && gl <= glASTCSRGB4x4+13 {
		return enumOrder[gl-glASTCSRGB4x4], true, true
	}
	return Footprint{}, false, false
}

// ── KTX2 ─────────────────────────────────────────────────────────────

// KTX2Magic is the twelve-byte KTX2 identifier.
var KTX2Magic = [12]byte{0xAB, 0x4B, 0x54, 0x58, 0x20, 0x32, 0x30, 0xBB,
	0x0D, 0x0A, 0x1A, 0x0A}

// KTX2 supercompression schemes.
const (
	SupercompressionNone    = 0
	SupercompressionBasisLZ = 1
	SupercompressionZstd    = 2
	SupercompressionZlib    = 3
)

// KTX2Level is one mip level in a KTX2 file.
type KTX2Level struct {
	Offset int
	Length int
	// UncompressedLength is what the level expands to when the file is
	// supercompressed; it equals Length when it is not.
	UncompressedLength int
	// Width and Height are the level's dimensions, halved per level and
	// clamped at 1.
	Width  int
	Height int
}

// KTX2Info is what a KTX2 header says about an ASTC texture.
type KTX2Info struct {
	VkFormat  uint32
	Footprint Footprint
	SRGB      bool
	// IsASTC is false when the file is a valid KTX2 holding some other
	// format, which is not an error, just not ours.
	IsASTC                 bool
	Width                  int
	Height                 int
	Layers                 int
	Faces                  int
	SupercompressionScheme uint32
	Levels                 []KTX2Level
}

// SupercompressionName is the human name of the scheme.
func (k KTX2Info) SupercompressionName() string {
	switch k.SupercompressionScheme {
	case SupercompressionNone:
		return "none"
	case SupercompressionBasisLZ:
		return "BasisLZ"
	case SupercompressionZstd:
		return "zstd"
	case SupercompressionZlib:
		return "zlib"
	}
	return fmt.Sprintf("unknown scheme %d", k.SupercompressionScheme)
}

// IsKTX2 reports whether data carries the KTX2 identifier.
func IsKTX2(data []byte) bool {
	if len(data) < len(KTX2Magic) {
		return false
	}
	for i, c := range KTX2Magic {
		if data[i] != c {
			return false
		}
	}
	return true
}

// ktx2FixedHeader is the size of the header before the level index.
const ktx2FixedHeader = 80

// maxKTX2Levels caps the level index. A texture cannot have more mip levels
// than the log of its largest legal side, so anything past this is a forged
// header trying to make the parser allocate.
const maxKTX2Levels = 32

// ParseKTX2 reads a KTX2 header and level index.
func ParseKTX2(data []byte) (KTX2Info, error) {
	var k KTX2Info
	if !IsKTX2(data) {
		return k, ErrMagic
	}
	if len(data) < ktx2FixedHeader {
		return k, ErrHeader
	}
	u32 := func(at int) uint32 { return binary.LittleEndian.Uint32(data[at : at+4]) }
	u64 := func(at int) uint64 { return binary.LittleEndian.Uint64(data[at : at+8]) }

	k.VkFormat = u32(12)
	k.Width = int(u32(20))
	k.Height = int(u32(24))
	k.Layers = int(u32(32))
	k.Faces = int(u32(36))
	levelCount := int(u32(40))
	k.SupercompressionScheme = u32(44)

	if fp, srgb, ok := FootprintForVkFormat(k.VkFormat); ok {
		k.Footprint = fp
		k.SRGB = srgb
		k.IsASTC = true
	}
	if k.Height == 0 {
		// A 1D texture; treat it as one row so the block maths still works.
		k.Height = 1
	}
	if k.Width <= 0 || k.Width > maxSide || k.Height > maxSide {
		return k, ErrDims
	}
	if levelCount == 0 {
		// Zero means "generate mips at load time"; level 0 is still present.
		levelCount = 1
	}
	if levelCount < 0 || levelCount > maxKTX2Levels {
		return k, ErrHeader
	}
	if len(data) < ktx2FixedHeader+levelCount*24 {
		return k, ErrHeader
	}

	w, h := k.Width, k.Height
	for i := 0; i < levelCount; i++ {
		at := ktx2FixedHeader + i*24
		off := u64(at)
		len0 := u64(at + 8)
		unc := u64(at + 16)
		if off > uint64(len(data)) || len0 > uint64(len(data)) ||
			off+len0 > uint64(len(data)) {
			return k, fmt.Errorf("%w: level %d runs past the end of the file",
				ErrHeader, i)
		}
		k.Levels = append(k.Levels, KTX2Level{
			Offset:             int(off),
			Length:             int(len0),
			UncompressedLength: int(unc),
			Width:              w,
			Height:             h,
		})
		if w > 1 {
			w /= 2
		}
		if h > 1 {
			h /= 2
		}
	}
	return k, nil
}

// DecodeKTX2Level decodes one already-decompressed mip level.
//
// The caller owns supercompression: this package has no business importing a
// zstd decoder, and the assetscan pipeline already has one wired up.
func DecodeKTX2Level(k KTX2Info, level int, payload []byte) (*Image, Stats, error) {
	if !k.IsASTC {
		return nil, Stats{}, fmt.Errorf("%w: vkFormat %d is not ASTC",
			ErrFootprint, k.VkFormat)
	}
	if level < 0 || level >= len(k.Levels) {
		return nil, Stats{}, ErrHeader
	}
	l := k.Levels[level]
	return DecodeWithStats(payload, l.Width, l.Height, k.Footprint, k.SRGB)
}

// GuessFootprint infers a footprint from a payload size and known dimensions.
//
// This is for the case that actually dominates in the wild: a .sctx or a raw
// blob where the dimensions are known from a sibling field but the footprint
// is not recorded anywhere. Exactly one legal footprint usually produces the
// observed byte count, and when more than one does the ambiguity is reported
// rather than resolved by guessing.
func GuessFootprint(payloadLen, width, height int) (Footprint, bool) {
	if payloadLen <= 0 || width <= 0 || height <= 0 {
		return Footprint{}, false
	}
	var hit Footprint
	count := 0
	for _, f := range footprints2D {
		xb := (width + f.Width - 1) / f.Width
		yb := (height + f.Height - 1) / f.Height
		if xb*yb*blockSize == payloadLen {
			hit = f
			count++
		}
	}
	return hit, count == 1
}
