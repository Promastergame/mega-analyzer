package preview

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

// ── helpers ────────────────────────────────────────────────────────────────

// samplePNG encodes a solid w x h PNG through the standard library, so the
// decode path under test is exercised against a genuinely valid file rather
// than a hand-assembled one.
func samplePNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 0x40, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

// undecodable is a buffer no decoder claims: it starts with 0x03, so it is not
// a PNG, JPEG, GIF, QOI or BMP magic.
func undecodable(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + 3)
	}
	return out
}

func qoiHeader(w, h uint32, channels byte) []byte {
	hdr := make([]byte, qoiHeadLen)
	copy(hdr[0:4], "qoif")
	binary.BigEndian.PutUint32(hdr[4:8], w)
	binary.BigEndian.PutUint32(hdr[8:12], h)
	hdr[12] = channels
	hdr[13] = 0
	return hdr
}

var qoiEnd = []byte{0, 0, 0, 0, 0, 0, 0, 1}

// bmp24 assembles an uncompressed 24bpp bitmap. height may be negative to
// request top-down row order.
func bmp24(width, height int32, rows []byte) []byte {
	const off = bmpFileHeadLen + bmpInfoHeadLen
	out := make([]byte, off, off+len(rows))
	out[0], out[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(out[2:6], uint32(off+len(rows)))
	binary.LittleEndian.PutUint32(out[10:14], off)
	binary.LittleEndian.PutUint32(out[14:18], bmpInfoHeadLen)
	binary.LittleEndian.PutUint32(out[18:22], uint32(width))
	binary.LittleEndian.PutUint32(out[22:26], uint32(height))
	binary.LittleEndian.PutUint16(out[26:28], 1)
	binary.LittleEndian.PutUint16(out[28:30], 24)
	binary.LittleEndian.PutUint32(out[30:34], 0)
	return append(out, rows...)
}

func rgbaAt(t *testing.T, img image.Image, x, y int) color.RGBA {
	t.Helper()
	r, g, b, a := img.At(x, y).RGBA()
	return color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
}

func expectRGBA(t *testing.T, img image.Image, x, y int, want color.RGBA, what string) {
	t.Helper()
	if got := rgbaAt(t, img, x, y); got != want {
		t.Fatalf("%s at (%d,%d) = %+v, want %+v", what, x, y, got, want)
	}
}

// ── options ────────────────────────────────────────────────────────────────

func TestOptionsNormalizeFillsDefaultsWithoutMutating(t *testing.T) {
	orig := Options{}
	n := orig.Normalize()
	if n.MaxDim != 1024 || n.MapMaxRows != 2048 {
		t.Fatalf("defaults = MaxDim %d, MapMaxRows %d", n.MaxDim, n.MapMaxRows)
	}
	// MapWidth deliberately stays zero: that is the signal for "choose one".
	if n.MapWidth != 0 {
		t.Fatalf("MapWidth was defaulted to %d, want 0 (auto)", n.MapWidth)
	}
	if orig.MaxDim != 0 || orig.MapMaxRows != 0 {
		t.Fatalf("Normalize mutated its receiver: %+v", orig)
	}

	explicit := Options{MaxDim: 64, MapMaxRows: 8, MapWidth: 16, NoFallback: true}.Normalize()
	if explicit.MaxDim != 64 || explicit.MapMaxRows != 8 || explicit.MapWidth != 16 || !explicit.NoFallback {
		t.Fatalf("explicit options were overwritten: %+v", explicit)
	}
}

// ── Render ─────────────────────────────────────────────────────────────────

func TestRenderPassesAPNGThroughUntouched(t *testing.T) {
	res, err := Render(samplePNG(t, 16, 8), Options{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if res.Decoder != "png" {
		t.Fatalf("Decoder = %q, want png", res.Decoder)
	}
	if res.Lossy {
		t.Fatalf("a real PNG decode was marked lossy")
	}
	if res.Width != 16 || res.Height != 8 || res.SrcWidth != 16 || res.SrcHeight != 8 {
		t.Fatalf("dimensions = %dx%d (src %dx%d)", res.Width, res.Height, res.SrcWidth, res.SrcHeight)
	}
	if res.Note != "" {
		t.Fatalf("an unscaled render carried a note: %q", res.Note)
	}
	if _, err := png.Decode(bytes.NewReader(res.PNG)); err != nil {
		t.Fatalf("output is not a decodable PNG: %v", err)
	}
}

func TestRenderDownscalesAndSaysSo(t *testing.T) {
	// 2000x10 at MaxDim 512: the wide side clamps to 512 and the short side
	// becomes 10*512/2000 = 2 by integer division.
	res, err := Render(samplePNG(t, 2000, 10), Options{MaxDim: 512})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if res.Width != 512 || res.Height != 2 {
		t.Fatalf("scaled to %dx%d, want 512x2", res.Width, res.Height)
	}
	if res.SrcWidth != 2000 || res.SrcHeight != 10 {
		t.Fatalf("source recorded as %dx%d", res.SrcWidth, res.SrcHeight)
	}
	if !strings.Contains(res.Note, "downscaled from 2000x10") {
		t.Fatalf("Note = %q", res.Note)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(res.PNG))
	if err != nil {
		t.Fatalf("png.DecodeConfig: %v", err)
	}
	if cfg.Width != 512 || cfg.Height != 2 {
		t.Fatalf("encoded PNG is %dx%d, disagreeing with Result", cfg.Width, cfg.Height)
	}
}

func TestRenderNeverRefusesUnlessAskedTo(t *testing.T) {
	data := undecodable(4096)

	res, err := Render(data, Options{})
	if err != nil {
		t.Fatalf("Render fell over on undecodable input: %v", err)
	}
	if res.Decoder != "bytemap" || !res.Lossy {
		t.Fatalf("Decoder = %q, Lossy = %v; want bytemap/true", res.Decoder, res.Lossy)
	}
	if !strings.Contains(res.Note, "byte map") {
		t.Fatalf("Note = %q, want it to admit this is not a decode", res.Note)
	}
	if _, err := png.Decode(bytes.NewReader(res.PNG)); err != nil {
		t.Fatalf("byte map is not a decodable PNG: %v", err)
	}

	// NoFallback is what the 3D texture path uses: a texture that cannot be
	// decoded should not silently become a byte map next to real thumbnails.
	if _, err := Render(data, Options{NoFallback: true}); !errors.Is(err, ErrWrongFormat) {
		t.Fatalf("NoFallback error = %v, want ErrWrongFormat", err)
	}
}

func TestCanDecodeIsACheapPreFilter(t *testing.T) {
	if !CanDecode(samplePNG(t, 4, 4)) {
		t.Fatalf("a real PNG was rejected")
	}
	if CanDecode(undecodable(512)) {
		t.Fatalf("random bytes were accepted")
	}
	if CanDecode(nil) {
		t.Fatalf("nil was accepted")
	}
	// Deliberately loose: CanDecode trusts a magic without validating the rest
	// of the header, because it exists to skip work, not to guarantee success.
	// Render still falls back correctly when the body turns out to be junk.
	if !CanDecode([]byte("qoif")) {
		t.Fatalf("a QOI magic was rejected")
	}
	if !CanDecode([]byte("BM\x00\x00")) {
		t.Fatalf("a BMP magic was rejected")
	}
	res, err := Render([]byte("BM\x00\x00"), Options{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if res.Decoder != "bytemap" {
		t.Fatalf("a bogus BMP decoded as %q instead of falling back", res.Decoder)
	}
}

// ── QOI ────────────────────────────────────────────────────────────────────

func TestDecodeQOIReadsRGBChunks(t *testing.T) {
	data := qoiHeader(2, 2, 4)
	data = append(data, qoiOpRGB, 255, 0, 0)
	data = append(data, qoiOpRGB, 0, 255, 0)
	data = append(data, qoiOpRGB, 0, 0, 255)
	data = append(data, qoiOpRGB, 255, 255, 0)
	data = append(data, qoiEnd...)

	img, err := DecodeQOI(data)
	if err != nil {
		t.Fatalf("DecodeQOI: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 2 || b.Dy() != 2 {
		t.Fatalf("bounds = %v, want 2x2", b)
	}
	// Alpha starts opaque and QOI_OP_RGB never touches it.
	expectRGBA(t, img, 0, 0, color.RGBA{R: 255, A: 255}, "pixel")
	expectRGBA(t, img, 1, 0, color.RGBA{G: 255, A: 255}, "pixel")
	expectRGBA(t, img, 0, 1, color.RGBA{B: 255, A: 255}, "pixel")
	expectRGBA(t, img, 1, 1, color.RGBA{R: 255, G: 255, A: 255}, "pixel")
}

func TestDecodeQOIHandlesRunsAndTheRunningIndex(t *testing.T) {
	// hash(10,20,30,255) = (30 + 100 + 210 + 2805) % 64 = 3145 % 64 = 9,
	// so QOI_OP_INDEX 9 must reproduce that colour after an intervening pixel.
	const a0, a1, a2 = 10, 20, 30
	data := qoiHeader(5, 1, 3)
	data = append(data, qoiOpRGB, a0, a1, a2) // pixel 0
	data = append(data, qoiOpRun|1)           // pixels 1 and 2 repeat it
	data = append(data, qoiOpRGB, 200, 100, 50)
	data = append(data, qoiOpIndex|9) // pixel 4 comes back from the index
	data = append(data, qoiEnd...)

	img, err := DecodeQOI(data)
	if err != nil {
		t.Fatalf("DecodeQOI: %v", err)
	}
	a := color.RGBA{R: a0, G: a1, B: a2, A: 255}
	b := color.RGBA{R: 200, G: 100, B: 50, A: 255}
	expectRGBA(t, img, 0, 0, a, "first pixel")
	expectRGBA(t, img, 1, 0, a, "run")
	expectRGBA(t, img, 2, 0, a, "run")
	expectRGBA(t, img, 3, 0, b, "second colour")
	expectRGBA(t, img, 4, 0, a, "index lookup")
}

func TestQOIHashMatchesTheSpecification(t *testing.T) {
	if got := qoiHash(color.RGBA{R: 10, G: 20, B: 30, A: 255}); got != 9 {
		t.Fatalf("qoiHash = %d, want 9", got)
	}
	if got := qoiHash(color.RGBA{A: 255}); got != (255*11)%64 {
		t.Fatalf("qoiHash(black) = %d", got)
	}
	// The result must always be a valid index into the 64-entry table.
	for i := 0; i < 256; i++ {
		c := color.RGBA{R: uint8(i), G: uint8(255 - i), B: uint8(i * 3), A: uint8(i)}
		if h := qoiHash(c); h < 0 || h > 63 {
			t.Fatalf("qoiHash(%+v) = %d, out of range", c, h)
		}
	}
}

func TestDecodeQOIRejectsBadInput(t *testing.T) {
	short := qoiHeader(2, 2, 4)
	short = append(short, qoiOpRGB, 1, 2, 3) // only one of four pixels

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"not qoi", []byte("nope, not an image at all"), ErrWrongFormat},
		{"too short for a header", []byte("qoif"), ErrWrongFormat},
		{"zero width", append(qoiHeader(0, 2, 4), qoiEnd...), ErrBadHeader},
		{"absurd width", append(qoiHeader(1<<20, 2, 4), qoiEnd...), ErrBadHeader},
		{"bad channel count", append(qoiHeader(2, 2, 2), qoiEnd...), ErrBadHeader},
		{"truncated pixels", short, ErrTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeQOI(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// ── BMP ────────────────────────────────────────────────────────────────────

func TestDecodeBMPFlipsBottomUpRows(t *testing.T) {
	// stride = ((2*24+31)/32)*4 = 8, so each row is 6 bytes of BGR plus 2 pad.
	rows := []byte{
		255, 0, 0, /* blue  */ 0, 255, 0 /* green */, 0, 0, // stored first = y=1
		0, 0, 255, /* red   */ 255, 255, 255 /* white */, 0, 0, // stored second = y=0
	}

	img, err := DecodeBMP(bmp24(2, 2, rows))
	if err != nil {
		t.Fatalf("DecodeBMP: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 2 || b.Dy() != 2 {
		t.Fatalf("bounds = %v, want 2x2", b)
	}
	expectRGBA(t, img, 0, 0, color.RGBA{R: 255, A: 255}, "top-left")
	expectRGBA(t, img, 1, 0, color.RGBA{R: 255, G: 255, B: 255, A: 255}, "top-right")
	expectRGBA(t, img, 0, 1, color.RGBA{B: 255, A: 255}, "bottom-left")
	expectRGBA(t, img, 1, 1, color.RGBA{G: 255, A: 255}, "bottom-right")

	// The same bytes with a negative height are top-down, so row order flips.
	topDown, err := DecodeBMP(bmp24(2, -2, rows))
	if err != nil {
		t.Fatalf("DecodeBMP (top-down): %v", err)
	}
	expectRGBA(t, topDown, 0, 0, color.RGBA{B: 255, A: 255}, "top-down top-left")
	expectRGBA(t, topDown, 0, 1, color.RGBA{R: 255, A: 255}, "top-down bottom-left")
}

func TestDecodeBMPReadsAnEightBitPalette(t *testing.T) {
	const headers = bmpFileHeadLen + bmpInfoHeadLen
	const paletteLen = 256 * 4
	const off = headers + paletteLen
	// stride = ((2*8+31)/32)*4 = 4
	out := make([]byte, off+4)
	out[0], out[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(out[2:6], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[10:14], off)
	binary.LittleEndian.PutUint32(out[14:18], bmpInfoHeadLen)
	binary.LittleEndian.PutUint32(out[18:22], 2)
	binary.LittleEndian.PutUint32(out[22:26], 1)
	binary.LittleEndian.PutUint16(out[26:28], 1)
	binary.LittleEndian.PutUint16(out[28:30], 8)

	// Palette entries are stored B, G, R, reserved.
	entry := headers + 1*4
	out[entry+0], out[entry+1], out[entry+2] = 0x10, 0x20, 0x30
	out[off+0], out[off+1] = 1, 0

	img, err := DecodeBMP(out)
	if err != nil {
		t.Fatalf("DecodeBMP: %v", err)
	}
	expectRGBA(t, img, 0, 0, color.RGBA{R: 0x30, G: 0x20, B: 0x10, A: 255}, "palette entry 1")
	expectRGBA(t, img, 1, 0, color.RGBA{A: 255}, "palette entry 0")
}

func TestDecodeBMPRejectsWhatItCannotHonestlyDecode(t *testing.T) {
	rle := bmp24(2, 2, make([]byte, 16))
	binary.LittleEndian.PutUint32(rle[30:34], 1) // BI_RLE8

	sixteenBit := bmp24(2, 2, make([]byte, 16))
	binary.LittleEndian.PutUint16(sixteenBit[28:30], 16)

	coreHeader := bmp24(2, 2, make([]byte, 16))
	binary.LittleEndian.PutUint32(coreHeader[14:18], 12) // BITMAPCOREHEADER

	// Declares 2x2x24bpp (needs 54+16 bytes) but supplies only 60.
	truncated := bmp24(2, 2, make([]byte, 6))

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"not a bitmap", []byte(strings.Repeat("x", 80)), ErrWrongFormat},
		{"shorter than the headers", []byte("BM"), ErrWrongFormat},
		{"rle compression", rle, ErrUnsupported},
		{"16 bits per pixel", sixteenBit, ErrUnsupported},
		{"legacy core header", coreHeader, ErrBadHeader},
		{"truncated pixel data", truncated, ErrTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeBMP(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRenderPicksUpQOIAndBMP(t *testing.T) {
	qoi := qoiHeader(2, 2, 4)
	for i := 0; i < 4; i++ {
		qoi = append(qoi, qoiOpRGB, byte(i*40), 0x20, 0x30)
	}
	qoi = append(qoi, qoiEnd...)

	res, err := Render(qoi, Options{})
	if err != nil {
		t.Fatalf("Render(qoi): %v", err)
	}
	if res.Decoder != "qoi" || res.Lossy {
		t.Fatalf("qoi went down the %q path (lossy=%v)", res.Decoder, res.Lossy)
	}

	res, err = Render(bmp24(2, 2, make([]byte, 16)), Options{})
	if err != nil {
		t.Fatalf("Render(bmp): %v", err)
	}
	if res.Decoder != "bmp" || res.Lossy {
		t.Fatalf("bmp went down the %q path (lossy=%v)", res.Decoder, res.Lossy)
	}
}

// ── byte map ───────────────────────────────────────────────────────────────

func TestRenderByteMapPaintsTheRemainderAsBackground(t *testing.T) {
	// 100 bytes at the automatic width of 32 gives ceil(100/32) = 4 rows, and
	// the last painted byte lands at (3,3), leaving (4,3) onwards unpainted.
	img, stride := RenderByteMap(undecodable(100), 0, 0)
	if stride != 1 {
		t.Fatalf("stride = %d, want 1 (no sampling needed)", stride)
	}
	if b := img.Bounds(); b.Dx() != 32 || b.Dy() != 4 {
		t.Fatalf("bounds = %v, want 32x4", b)
	}
	// An unpainted pixel must be the explicit background, never transparent
	// black, which would read as a run of 0x00 that is not in the file.
	expectRGBA(t, img, 4, 3, color.RGBA{R: 0x08, G: 0x08, B: 0x08, A: 255}, "unpainted remainder")
	if got := rgbaAt(t, img, 3, 3); got.A != 255 {
		t.Fatalf("last painted byte is not opaque: %+v", got)
	}
}

func TestRenderByteMapSamplesInsteadOfTruncating(t *testing.T) {
	// width 4 x maxRows 2 = capacity 8. 40 bytes needs stride 5 to fit, and
	// ceil(40/5) = 8 samples land in exactly 2 rows.
	img, stride := RenderByteMap(undecodable(40), 4, 2)
	if stride != 5 {
		t.Fatalf("stride = %d, want 5", stride)
	}
	if b := img.Bounds(); b.Dx() != 4 || b.Dy() != 2 {
		t.Fatalf("bounds = %v, want 4x2", b)
	}
}

func TestRenderByteMapReportsSamplingToTheUser(t *testing.T) {
	res, err := Render(undecodable(200000), Options{MapWidth: 4, MapMaxRows: 2})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(res.Note, "sampled") {
		t.Fatalf("Note = %q, want it to disclose sampling", res.Note)
	}
}

func TestRenderByteMapHandlesEmptyInput(t *testing.T) {
	img, stride := RenderByteMap(nil, 0, 0)
	if stride != 1 {
		t.Fatalf("stride = %d, want 1", stride)
	}
	if b := img.Bounds(); b.Dx() != 1 || b.Dy() != 1 {
		t.Fatalf("bounds = %v, want 1x1", b)
	}
	expectRGBA(t, img, 0, 0, mapZero, "empty buffer")
}

func TestByteColorSeparatesTheFourRegimes(t *testing.T) {
	cases := []struct {
		name string
		in   byte
		want color.RGBA
	}{
		{"zero", 0x00, mapZero},
		{"full", 0xFF, mapFull},
		{"printable", 'A', mapText},
		{"space", 0x20, mapText},
		{"tilde", 0x7E, mapText},
		{"control", 0x01, mapCtrl},
		{"high ramp start", 0x7F, mapHighA},
		{"high ramp end", 0xFE, mapHighB},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := byteColor(tc.in); got != tc.want {
				t.Fatalf("byteColor(%#x) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
	// Every byte must map to an opaque colour, or the PNG gains stray alpha.
	for i := 0; i < 256; i++ {
		if c := byteColor(byte(i)); c.A != 255 {
			t.Fatalf("byteColor(%#x) alpha = %d", i, c.A)
		}
	}
}

func TestMapWidthForBuckets(t *testing.T) {
	cases := map[int]int{0: 1, -5: 1, 1: 32, 1023: 32, 1024: 64, 16383: 64, 16384: 256, 1 << 20: 256}
	for in, want := range cases {
		if got := mapWidthFor(in); got != want {
			t.Fatalf("mapWidthFor(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestLerp8HitsBothEndpoints(t *testing.T) {
	if got := lerp8(0, 255, 0); got != 0 {
		t.Fatalf("lerp8 at t=0 = %d, want 0", got)
	}
	if got := lerp8(0, 255, 255); got != 255 {
		t.Fatalf("lerp8 at t=255 = %d, want 255", got)
	}
	// (0*127 + 254*128)/255 = 32512/255 = 127 under integer division.
	if got := lerp8(0, 254, 128); got != 127 {
		t.Fatalf("lerp8 midpoint = %d, want 127", got)
	}
}
