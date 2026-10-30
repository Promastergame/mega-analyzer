package media

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"math"
	"math/rand"
	"testing"
)

// ─── chi-squared distribution ────────────────────────────────────────────────

func TestChiSquaredUpperTail(t *testing.T) {
	// Critical values from standard chi-squared tables: at these statistics the
	// upper-tail probability is 0.05 for the given degrees of freedom.
	cases := []struct {
		df    int
		chi2  float64
		wantP float64
	}{
		{1, 3.8415, 0.05},
		{2, 5.9915, 0.05},
		{5, 11.0705, 0.05},
		{10, 18.3070, 0.05},
		{20, 31.4104, 0.05},
		{1, 6.6349, 0.01},
		{10, 23.2093, 0.01},
		{4, 1.0636, 0.90},
		{10, 4.8652, 0.90},
	}
	for _, c := range cases {
		got := chiSquaredUpperTail(c.chi2, c.df)
		if math.Abs(got-c.wantP) > 5e-3 {
			t.Errorf("chiSquaredUpperTail(%.4f, df=%d) = %.5f, want ~%.2f",
				c.chi2, c.df, got, c.wantP)
		}
	}
}

func TestChiSquaredUpperTailEdges(t *testing.T) {
	if p := chiSquaredUpperTail(0, 5); p != 1 {
		t.Errorf("chi2=0 must give p=1, got %v", p)
	}
	if p := chiSquaredUpperTail(-1, 5); p != 1 {
		t.Errorf("negative chi2 must give p=1, got %v", p)
	}
	if p := chiSquaredUpperTail(10, 0); p != 1 {
		t.Errorf("df=0 must give p=1, got %v", p)
	}

	// The tail must be monotonically decreasing in chi2 and stay in [0,1].
	prev := 1.0
	for chi2 := 0.5; chi2 < 60; chi2 += 0.5 {
		p := chiSquaredUpperTail(chi2, 8)
		if p < 0 || p > 1 {
			t.Fatalf("p out of range at chi2=%.1f: %v", chi2, p)
		}
		if p > prev+1e-12 {
			t.Fatalf("tail not monotone at chi2=%.1f: %v > %v", chi2, p, prev)
		}
		prev = p
	}
}

// ─── pairs-of-values statistic ───────────────────────────────────────────────

// TestPoVChiSquaredEmbeddedHistogram feeds the statistic a histogram whose
// pairs are balanced, which is exactly what LSB embedding produces. It must
// yield a small statistic and therefore a high p-value.
func TestPoVChiSquaredEmbeddedHistogram(t *testing.T) {
	h := &jpegACHistogram{blocks: 100}
	// Monotone decay across magnitudes (natural), but each pair internally
	// balanced (embedded).
	for m := 1; m <= 40; m++ {
		n := 400 / m
		for _, sign := range []int{1, -1} {
			for i := 0; i < n; i++ {
				h.add(sign * (2 * m))
				h.add(sign * (2*m + 1))
			}
		}
	}

	chi2, df, used := jpegPoVChiSquared(h)
	if df < minPoVDegreesOfFreedom {
		t.Fatalf("expected enough degrees of freedom, got df=%d", df)
	}
	if used == 0 {
		t.Fatal("expected coefficients to be counted")
	}
	p := chiSquaredUpperTail(chi2, df)
	if p < povEmbeddingPValue {
		t.Errorf("balanced pairs should look embedded: chi2=%.3f df=%d p=%.4f, want p>=%.2f",
			chi2, df, p, povEmbeddingPValue)
	}
}

// TestPoVChiSquaredNaturalHistogram feeds the statistic a steeply monotone
// histogram, the natural JPEG shape where the even member of each pair heavily
// outnumbers the odd one. It must produce a large statistic and a low p-value.
func TestPoVChiSquaredNaturalHistogram(t *testing.T) {
	h := &jpegACHistogram{blocks: 100}
	for m := 1; m <= 40; m++ {
		even := 800 / m
		odd := even / 4 // strongly skewed within the pair
		if odd < 1 {
			odd = 1
		}
		for _, sign := range []int{1, -1} {
			for i := 0; i < even; i++ {
				h.add(sign * (2 * m))
			}
			for i := 0; i < odd; i++ {
				h.add(sign * (2*m + 1))
			}
		}
	}

	chi2, df, _ := jpegPoVChiSquared(h)
	p := chiSquaredUpperTail(chi2, df)
	if p >= povEmbeddingPValue {
		t.Errorf("skewed pairs must not look embedded: chi2=%.3f df=%d p=%.4f",
			chi2, df, p)
	}
}

func TestPoVChiSquaredIgnoresSparsePairs(t *testing.T) {
	h := &jpegACHistogram{blocks: 10}
	// Every pair below minPoVExpected — nothing should qualify.
	for m := 1; m <= 40; m++ {
		h.add(2 * m)
		h.add(2*m + 1)
	}
	chi2, df, used := jpegPoVChiSquared(h)
	if chi2 != 0 || df != 0 || used != 0 {
		t.Errorf("sparse pairs must be excluded, got chi2=%v df=%v used=%v", chi2, df, used)
	}
}

// TestPoVChiSquaredSkipsUnusableCoefficients verifies that 0/±1 are never
// paired, since JSteg-family embedders leave them alone.
func TestPoVChiSquaredSkipsUnusableCoefficients(t *testing.T) {
	h := &jpegACHistogram{blocks: 10}
	for i := 0; i < 5000; i++ {
		h.add(0)
		h.add(1)
		h.add(-1)
	}
	chi2, df, used := jpegPoVChiSquared(h)
	if used != 0 || df != 0 || chi2 != 0 {
		t.Errorf("0/±1 must be excluded from the test, got chi2=%v df=%v used=%v", chi2, df, used)
	}
}

func TestACHistogramBounds(t *testing.T) {
	h := &jpegACHistogram{}
	// Out-of-range values must be dropped rather than panicking.
	h.add(jpegACHistOffset)
	h.add(-jpegACHistOffset - 1)
	h.add(1 << 20)
	if h.total != 0 {
		t.Errorf("out-of-range coefficients must be ignored, total=%d", h.total)
	}
	if got := h.at(1 << 20); got != 0 {
		t.Errorf("at() out of range must be 0, got %d", got)
	}

	h.add(7)
	if h.at(7) != 1 || h.total != 1 {
		t.Errorf("in-range add failed: at(7)=%d total=%d", h.at(7), h.total)
	}
}

// ─── entropy decoder against real JPEGs ──────────────────────────────────────

func encodeJPEG(t *testing.T, img image.Image, quality int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		t.Fatalf("jpeg.Encode: %v", err)
	}
	return buf.Bytes()
}

// noisyGray produces a grayscale image with enough detail to generate a broad
// spread of AC coefficients (a flat image would encode to almost nothing).
func noisyGray(w, h int, seed int64) *image.Gray {
	rng := rand.New(rand.NewSource(seed))
	img := image.NewGray(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := (x*7+y*13)%256/2 + rng.Intn(128)
			img.SetGray(x, y, color.Gray{Y: uint8(v)})
		}
	}
	return img
}

func noisyRGBA(w, h int, seed int64) *image.RGBA {
	rng := rand.New(rand.NewSource(seed))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{
				R: uint8(rng.Intn(256)),
				G: uint8((x*3 + rng.Intn(90)) % 256),
				B: uint8((y*5 + rng.Intn(90)) % 256),
				A: 255,
			})
		}
	}
	return img
}

// TestExtractACHistogramGrayscale exercises the non-interleaved (single
// component) scan path and checks the decoded block count against the geometry
// implied by the image dimensions.
func TestExtractACHistogramGrayscale(t *testing.T) {
	const w, h = 64, 64
	data := encodeJPEG(t, noisyGray(w, h, 1), 90)

	hist, ok := extractJPEGACHistogram(data)
	if !ok {
		t.Fatal("expected grayscale baseline JPEG to decode")
	}

	// 64x64 luma at 1x1 sampling = 8x8 blocks.
	if want := 64; hist.blocks != want {
		t.Errorf("blocks = %d, want %d", hist.blocks, want)
	}
	if hist.total == 0 {
		t.Error("expected non-zero AC coefficients from a noisy image")
	}
}

// TestExtractACHistogramColor exercises the interleaved multi-component MCU
// path, including chroma subsampling.
func TestExtractACHistogramColor(t *testing.T) {
	const w, h = 64, 64
	data := encodeJPEG(t, noisyRGBA(w, h, 2), 90)

	hist, ok := extractJPEGACHistogram(data)
	if !ok {
		t.Fatal("expected color baseline JPEG to decode")
	}
	if hist.blocks == 0 || hist.total == 0 {
		t.Fatalf("expected coefficients, got blocks=%d total=%d", hist.blocks, hist.total)
	}

	// Go's encoder uses 4:2:0 for color: per 16x16 MCU that is 4 luma blocks
	// plus one block each of Cb and Cr. 64x64 gives 4x4 = 16 MCUs.
	if want := 16 * 6; hist.blocks != want {
		t.Errorf("blocks = %d, want %d (4:2:0, 16 MCUs x 6 blocks)", hist.blocks, want)
	}
}

// TestExtractACHistogramNonSquare checks the geometry maths on dimensions that
// are not a whole number of MCUs, where the encoder pads the final row/column.
func TestExtractACHistogramNonSquare(t *testing.T) {
	data := encodeJPEG(t, noisyRGBA(70, 34, 3), 85)

	hist, ok := extractJPEGACHistogram(data)
	if !ok {
		t.Fatal("expected non-MCU-aligned JPEG to decode")
	}
	// ceil(70/16) = 5 MCUs across, ceil(34/16) = 3 down.
	if want := 5 * 3 * 6; hist.blocks != want {
		t.Errorf("blocks = %d, want %d", hist.blocks, want)
	}
}

// TestExtractACHistogramRejectsNonBaseline confirms that frames the decoder
// cannot handle are refused instead of producing garbage coefficients.
func TestExtractACHistogramRejectsNonBaseline(t *testing.T) {
	// Rewrite a valid baseline file's SOF0 into SOF2 (progressive).
	data := encodeJPEG(t, noisyGray(32, 32, 4), 80)
	prog := append([]byte(nil), data...)
	found := false
	for i := 0; i+1 < len(prog); i++ {
		if prog[i] == 0xFF && prog[i+1] == 0xC0 {
			prog[i+1] = 0xC2
			found = true
			break
		}
	}
	if !found {
		t.Fatal("test setup: no SOF0 marker in encoded JPEG")
	}
	if _, ok := extractJPEGACHistogram(prog); ok {
		t.Error("progressive frame must be rejected")
	}
}

func TestExtractACHistogramRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":       nil,
		"too short":   {0xFF, 0xD8},
		"bad magic":   bytes.Repeat([]byte{0x41}, 2048),
		"no SOS":      append([]byte{0xFF, 0xD8}, bytes.Repeat([]byte{0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00}, 4)...),
		"header only": {0xFF, 0xD8, 0xFF, 0xD9},
	}
	for name, data := range cases {
		if _, ok := extractJPEGACHistogram(data); ok {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// TestExtractACHistogramTruncated verifies that cutting the scan data short
// does not panic. Whether a partial decode is accepted depends on how many
// blocks survived, so both outcomes are valid — the point is that it is safe.
func TestExtractACHistogramTruncated(t *testing.T) {
	data := encodeJPEG(t, noisyGray(64, 64, 5), 90)
	for _, frac := range []float64{0.3, 0.5, 0.7, 0.9} {
		cut := int(float64(len(data)) * frac)
		hist, ok := extractJPEGACHistogram(data[:cut])
		if ok && hist.blocks == 0 {
			t.Errorf("frac=%.1f: reported ok with zero blocks", frac)
		}
	}
}

// TestJPEGFrameDimensions checks dimension recovery, including the stricter
// non-baseline rejection this decoder needs.
func TestJPEGFrameDimensions(t *testing.T) {
	data := encodeJPEG(t, noisyGray(37, 91, 6), 80)
	w, h, ok := jpegFrameDimensions(data)
	if !ok || w != 37 || h != 91 {
		t.Errorf("got %dx%d ok=%v, want 37x91", w, h, ok)
	}

	if _, _, ok := jpegFrameDimensions([]byte{0xFF, 0xD8}); ok {
		t.Error("expected failure on truncated input")
	}
	if _, _, ok := jpegFrameDimensions(bytes.Repeat([]byte{0}, 64)); ok {
		t.Error("expected failure on non-JPEG input")
	}
}

// ─── end-to-end detector behaviour ───────────────────────────────────────────

// TestDCTChiSquaredCleanJPEG asserts no false positive on an ordinary photo-like
// image, the property that matters most for a detector wired into reporting.
func TestDCTChiSquaredCleanJPEG(t *testing.T) {
	for _, quality := range []int{60, 75, 90} {
		data := encodeJPEG(t, noisyRGBA(96, 96, int64(quality)), quality)
		if sigs := detectDCTChiSquared(data); len(sigs) != 0 {
			t.Errorf("quality=%d: expected no stego signal on clean JPEG, got %+v", quality, sigs)
		}
	}
}

// TestDCTChiSquaredFallback covers the path where coefficients cannot be
// recovered: a high-entropy blob that is large enough to test but is not a
// decodable JPEG must produce the coarse entropy signal instead of nothing.
func TestDCTChiSquaredFallback(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	blob := make([]byte, 8192)
	for i := range blob {
		blob[i] = byte(rng.Intn(256))
	}
	sigs := detectDCTChiSquared(blob)
	if len(sigs) != 1 || sigs[0].Method != "dct_entropy_anomaly" {
		t.Fatalf("expected entropy fallback signal, got %+v", sigs)
	}
	if sigs[0].Confidence != 0.4 {
		t.Errorf("fallback confidence = %v, want 0.4", sigs[0].Confidence)
	}
}

func TestDCTChiSquaredShortInput(t *testing.T) {
	if sigs := detectDCTChiSquared(nil); sigs != nil {
		t.Errorf("nil input must give nil, got %+v", sigs)
	}
	if sigs := detectDCTChiSquared(make([]byte, 1023)); sigs != nil {
		t.Errorf("sub-1024-byte input must give nil, got %+v", sigs)
	}
}

// TestDCTChiSquaredDetectsEmbedding is the positive case: it takes a real JPEG,
// rewrites its entropy-coded coefficients so that pairs-of-values become
// balanced (what LSB embedding does), and checks the detector fires.
//
// Rather than re-encoding — which would need a full JPEG writer — this drives
// the statistic directly with a histogram built from the real file's block
// count, so the reported evidence stays consistent with a genuine image.
func TestDCTChiSquaredDetectsEmbedding(t *testing.T) {
	data := encodeJPEG(t, noisyGray(96, 96, 8), 90)
	hist, ok := extractJPEGACHistogram(data)
	if !ok {
		t.Fatal("setup: expected JPEG to decode")
	}

	// Balance every pair, preserving each pair's total mass.
	embedded := &jpegACHistogram{blocks: hist.blocks}
	for m := 1; m*2+1 < jpegACHistOffset; m++ {
		for _, sign := range []int{1, -1} {
			lo := sign * (2 * m)
			hi := sign * (2*m + 1)
			total := int(hist.at(lo)) + int(hist.at(hi))
			if total == 0 {
				continue
			}
			for i := 0; i < total; i++ {
				if i%2 == 0 {
					embedded.add(lo)
				} else {
					embedded.add(hi)
				}
			}
		}
	}

	chi2, df, used := jpegPoVChiSquared(embedded)
	if df < minPoVDegreesOfFreedom {
		t.Skipf("image produced too few populated pairs (df=%d) for a meaningful test", df)
	}
	p := chiSquaredUpperTail(chi2, df)
	if p < povEmbeddingPValue {
		t.Errorf("balanced real-image histogram should look embedded: chi2=%.3f df=%d p=%.4f used=%d",
			chi2, df, p, used)
	}
}

// TestDetectSteganographyJPEGRouting confirms the dispatcher sends JPEG through
// the DCT path and that a clean file stays clean end to end.
func TestDetectSteganographyJPEGRouting(t *testing.T) {
	data := encodeJPEG(t, noisyRGBA(96, 96, 9), 85)
	if sigs := DetectSteganography(data, TypeJPEG); len(sigs) != 0 {
		t.Errorf("clean JPEG should produce no stego signals, got %+v", sigs)
	}
}

// TestHuffmanTableRejectsInvalid covers the guards on malformed DHT data.
func TestHuffmanTableRejectsInvalid(t *testing.T) {
	var tb jpegHuffTable
	if tb.build(make([]byte, 15), []byte{1}) {
		t.Error("wrong counts length must be rejected")
	}
	if tb.build(make([]byte, 16), nil) {
		t.Error("all-zero counts must be rejected")
	}
	counts := make([]byte, 16)
	counts[0] = 5
	if tb.build(counts, []byte{1, 2}) {
		t.Error("counts exceeding available values must be rejected")
	}

	counts = make([]byte, 16)
	counts[0] = 2
	if !tb.build(counts, []byte{0xAA, 0xBB}) {
		t.Fatal("valid table must build")
	}
	if !tb.valid || len(tb.vals) != 2 {
		t.Errorf("unexpected table state: valid=%v vals=%v", tb.valid, tb.vals)
	}
}

// TestBitReaderStuffingAndMarkers checks the two scan-data quirks the reader
// has to handle: 0xFF00 byte stuffing, and markers ending the stream.
func TestBitReaderStuffingAndMarkers(t *testing.T) {
	// 0xFF 0x00 must yield the eight bits of a literal 0xFF.
	br := &jpegBitReader{data: []byte{0xFF, 0x00}}
	for i := 0; i < 8; i++ {
		bit, ok := br.readBit()
		if !ok || bit != 1 {
			t.Fatalf("bit %d: got %v ok=%v, want 1", i, bit, ok)
		}
	}
	if _, ok := br.readBit(); ok {
		t.Error("expected end of stream after stuffed byte")
	}

	// A real marker terminates the readable stream.
	br = &jpegBitReader{data: []byte{0xFF, 0xD9}}
	if _, ok := br.readBit(); ok {
		t.Error("EOI marker must end the bit stream")
	}

	// Restart markers are consumed by restart(), other markers are not.
	br = &jpegBitReader{data: []byte{0xFF, 0xD0, 0x80}}
	if !br.restart() {
		t.Error("expected restart marker to be consumed")
	}
	br = &jpegBitReader{data: []byte{0xFF, 0xD9}}
	if br.restart() {
		t.Error("EOI must not be treated as a restart marker")
	}
}

func TestJPEGExtend(t *testing.T) {
	cases := []struct {
		v    int32
		s    byte
		want int32
	}{
		{0, 0, 0},
		{1, 1, 1},
		{0, 1, -1},
		{3, 2, 3},
		{2, 2, 2},
		{1, 2, -2},
		{0, 2, -3},
		{7, 3, 7},
		{0, 3, -7},
	}
	for _, c := range cases {
		if got := jpegExtend(c.v, c.s); got != c.want {
			t.Errorf("jpegExtend(%d, %d) = %d, want %d", c.v, c.s, got, c.want)
		}
	}
}

func TestCeilDiv(t *testing.T) {
	cases := []struct{ a, b, want int }{
		{0, 8, 0},
		{1, 8, 1},
		{8, 8, 1},
		{9, 8, 2},
		{70, 16, 5},
		{34, 16, 3},
		{5, 0, 0},
		{5, -1, 0},
	}
	for _, c := range cases {
		if got := ceilDiv(c.a, c.b); got != c.want {
			t.Errorf("ceilDiv(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
