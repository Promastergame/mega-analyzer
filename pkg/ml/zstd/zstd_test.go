package zstd

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// corpusFor regenerates the plaintext a fixture was built from. Keeping the
// generators here instead of embedding megabytes of golden output means the
// test data stays small, and it double-checks that the Go and Python
// generators agree: if they did not, every fixture would fail at once.
func corpusFor(t *testing.T, name string) []byte {
	t.Helper()
	switch name {
	case "repeat":
		return bytes.Repeat([]byte("ABCDEFGH"), 4096)
	case "ramp":
		b := make([]byte, 65536)
		for i := range b {
			b[i] = byte(i*37 + 11)
		}
		return b
	case "text":
		var sb bytes.Buffer
		for i := 0; i < 200; i++ {
			fmt.Fprintf(&sb, "line %d: the quick brown fox jumps over the lazy dog; asset %04d needs a texture\n", i, (i*7)%1000)
		}
		return sb.Bytes()
	case "lcg":
		b := make([]byte, 2048)
		x := uint32(1)
		for i := range b {
			x = (x*1103515245 + 12345) & 0x7FFFFFFF
			b[i] = byte(x >> 16)
		}
		return b
	case "text+repeat":
		out := append([]byte(nil), corpusFor(t, "text")...)
		return append(out, corpusFor(t, "repeat")...)
	}
	t.Fatalf("unknown corpus %q", name)
	return nil
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	for _, f := range goldenFixtures {
		if f.name == name {
			blob, err := base64.StdEncoding.DecodeString(f.b64)
			if err != nil {
				t.Fatalf("fixture %s is not valid base64: %v", name, err)
			}
			return blob
		}
	}
	t.Fatalf("no fixture named %q", name)
	return nil
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test: %v", err)
	}
	return b
}

// ── the real thing ────────────────────────────────────────────────────────

// TestGoldenFixturesDecodeExactly is the test that matters. Every blob came
// out of the reference zstd tool at a different compression level, so between
// them they exercise raw blocks, run-length blocks, single-stream and
// four-stream Huffman literals, all four sequence table modes, table reuse
// across blocks, the three repeat offsets, long-distance matching, frame
// checksums, concatenated frames and skippable frames.
func TestGoldenFixturesDecodeExactly(t *testing.T) {
	if len(goldenFixtures) == 0 {
		t.Fatal("no fixtures compiled in")
	}
	for _, f := range goldenFixtures {
		t.Run(f.name, func(t *testing.T) {
			blob, err := base64.StdEncoding.DecodeString(f.b64)
			if err != nil {
				t.Fatalf("bad base64: %v", err)
			}
			want := corpusFor(t, f.corpus)
			got, err := Decompress(blob)
			if err != nil {
				t.Fatalf("Decompress: %v", err)
			}
			if len(got) != len(want) {
				t.Fatalf("decoded %d bytes, want %d", len(got), len(want))
			}
			if !bytes.Equal(got, want) {
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("first difference at byte %d: got %#02x want %#02x", i, got[i], want[i])
					}
				}
			}
		})
	}
}

// TestDecoderReuseAcrossFixtures covers the scanning path: one Decoder walking
// many files must not leak state between them. A stale Huffman table or repeat
// offset would corrupt the second file, not the first.
func TestDecoderReuseAcrossFixtures(t *testing.T) {
	dec := NewDecoder()
	for round := 0; round < 2; round++ {
		for _, f := range goldenFixtures {
			blob, err := base64.StdEncoding.DecodeString(f.b64)
			if err != nil {
				t.Fatalf("bad base64: %v", err)
			}
			got, err := dec.Decompress(blob)
			if err != nil {
				t.Fatalf("round %d, %s: %v", round, f.name, err)
			}
			if !bytes.Equal(got, corpusFor(t, f.corpus)) {
				t.Fatalf("round %d, %s: output differs on a reused decoder", round, f.name)
			}
		}
	}
}

// TestDecoderDoesNotAliasPreviousResult guards the buffer reuse: a caller must
// be able to hold on to one result while decoding the next file.
func TestDecoderDoesNotAliasPreviousResult(t *testing.T) {
	dec := NewDecoder()
	first, err := dec.Decompress(fixture(t, "repeat_l1"))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	keep := append([]byte(nil), first...)
	if _, err := dec.Decompress(fixture(t, "text_l9")); err != nil {
		t.Fatalf("second: %v", err)
	}
	if !bytes.Equal(first, keep) {
		t.Fatal("the second decode overwrote the first result")
	}
}

// ── hand-built frames ───────────────────────────────────────────────────
//
// A real compressor never emits a raw or run-length block for input this
// small, so these are assembled by hand. Each byte sequence below was checked
// against an independent implementation before being written down.

func TestRawBlockFrame(t *testing.T) {
	// magic | desc 0x20 single segment | content size 5 | raw block | "hello"
	got, err := Decompress(mustHex(t, "28b52ffd200529000068656c6c6f"))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want \"hello\"", got)
	}
}

func TestRLEBlockFrame(t *testing.T) {
	// One byte repeated 100 times, which costs ten bytes of frame.
	got, err := Decompress(mustHex(t, "28b52ffd20642303005a"))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{'Z'}, 100)) {
		t.Fatalf("got %d bytes, want 100 copies of Z", len(got))
	}
}

func TestTwoBlocksInOneFrame(t *testing.T) {
	// A raw block that is not the last, then a run-length block that is.
	got, err := Decompress(mustHex(t, "28b52ffd20081800006162632b000051"))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if string(got) != "abcQQQQQ" {
		t.Fatalf("got %q, want \"abcQQQQQ\"", got)
	}
}

func TestReservedBlockTypeRejected(t *testing.T) {
	_, err := Decompress(mustHex(t, "28b52ffd20052f000068656c6c6f"))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
}

func TestDictionaryFrameRejected(t *testing.T) {
	// Descriptor 0x21 declares a one-byte dictionary id. There is no way to
	// decode such a frame without the dictionary, so it must be refused
	// clearly rather than producing plausible garbage.
	_, err := Decompress(mustHex(t, "28b52ffd21070529000068656c6c6f"))
	if !errors.Is(err, ErrDictionary) {
		t.Fatalf("want ErrDictionary, got %v", err)
	}
}

func TestReservedHeaderBitRejected(t *testing.T) {
	// Bit 3 of the descriptor is reserved. Anything that sets it is not a
	// zstd frame, which is what stops a random four-byte match inside an
	// image from being treated as one.
	_, err := Decompress(mustHex(t, "28b52ffd280529000068656c6c6f"))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
}

func TestContentSizeMismatchRejected(t *testing.T) {
	// The header claims nine bytes; the block produces five.
	_, err := Decompress(mustHex(t, "28b52ffd200929000068656c6c6f"))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
}

// ── damage detection ────────────────────────────────────────────────────

func TestChecksumMismatchRejected(t *testing.T) {
	blob := append([]byte(nil), fixture(t, "repeat_l1")...)
	blob[len(blob)-1] ^= 0xFF
	_, err := Decompress(blob)
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("want ErrChecksum, got %v", err)
	}
}

func TestNoCheckFrameCarriesNoChecksum(t *testing.T) {
	h, err := ReadHeader(fixture(t, "text_l3_nocheck"))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if h.HasChecksum {
		t.Fatal("a --no-check frame should not declare a checksum")
	}
	h2, err := ReadHeader(fixture(t, "text_l1"))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !h2.HasChecksum {
		t.Fatal("a default frame should declare a checksum")
	}
}

func TestTruncatedInputRejected(t *testing.T) {
	full := fixture(t, "text_l19")
	for _, cut := range []int{6, 12, len(full) / 2, len(full) - 2} {
		_, err := Decompress(full[:cut])
		if err == nil {
			t.Fatalf("cut to %d bytes decoded without error", cut)
		}
		if !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrCorrupt) {
			t.Fatalf("cut to %d bytes: unexpected error kind: %v", cut, err)
		}
	}
}

func TestNotAZstdStream(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte("hi"),
		[]byte("\x89PNG\r\n\x1a\n"),
		bytes.Repeat([]byte{0}, 64),
	} {
		if _, err := Decompress(in); !errors.Is(err, ErrMagic) {
			t.Fatalf("want ErrMagic for %q, got %v", in, err)
		}
	}
}

func TestDecompressLimitStopsRunawayOutput(t *testing.T) {
	// repeat_l19 is thirty bytes that expand to thirty-two kilobytes. That
	// ratio is exactly why an output limit is not optional.
	_, err := DecompressLimit(fixture(t, "repeat_l19"), 4096)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if _, err := DecompressLimit(fixture(t, "repeat_l19"), 32768); err != nil {
		t.Fatalf("a limit equal to the content size should pass: %v", err)
	}
}

// ── headers and discovery ────────────────────────────────────────────────

func TestDecodedSizeHint(t *testing.T) {
	n, ok := DecodedSize(fixture(t, "repeat_l1"))
	if !ok || n != 32768 {
		t.Fatalf("got %d, %v; want 32768, true", n, ok)
	}
	// A leading skippable frame must not hide the real one.
	n, ok = DecodedSize(fixture(t, "skippable"))
	if !ok || n != 32768 {
		t.Fatalf("with a skippable frame first: got %d, %v", n, ok)
	}
}

func TestWindowSizeArithmetic(t *testing.T) {
	// Not single segment, so a window descriptor byte follows. 0x01 means
	// exponent 10 plus one eighth: 1024 + 128.
	h, err := ReadHeader(mustHex(t, "28b52ffd0001"))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if h.WindowSize != 1152 {
		t.Fatalf("WindowSize = %d, want 1152", h.WindowSize)
	}
	if h.HeaderSize != 6 {
		t.Fatalf("HeaderSize = %d, want 6", h.HeaderSize)
	}
	if h.ContentSizeKnown {
		t.Fatal("this frame declares no content size")
	}
	if h.BlockSizeMax != 1152 {
		t.Fatalf("BlockSizeMax = %d, want the window size 1152", h.BlockSizeMax)
	}
}

func TestFindFrameLocatesEmbeddedFrame(t *testing.T) {
	// This is the .sctx shape: a small proprietary head, then one zstd frame.
	head := []byte{0x34, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 'S', 'C', 'T', 'X'}
	inner := fixture(t, "text_l9")
	blob := append(append([]byte(nil), head...), inner...)

	at := FindFrame(blob)
	if at != len(head) {
		t.Fatalf("FindFrame = %d, want %d", at, len(head))
	}
	dec := NewDecoder()
	got, next, err := dec.DecompressAt(blob, at)
	if err != nil {
		t.Fatalf("DecompressAt: %v", err)
	}
	if !bytes.Equal(got, corpusFor(t, "text")) {
		t.Fatal("embedded frame decoded to the wrong bytes")
	}
	if next != len(blob) {
		t.Fatalf("next = %d, want %d", next, len(blob))
	}
	if FindFrame(head) != -1 {
		t.Fatal("FindFrame found a frame in a header-only buffer")
	}
}

func TestIsFrameRejectsCoincidentalMagic(t *testing.T) {
	// The magic bytes followed by a descriptor with the reserved bit set.
	// Four matching bytes inside a texture are common; a header check is what
	// separates a real frame from noise.
	if IsFrame(mustHex(t, "28b52ffd28")) {
		t.Fatal("a reserved descriptor bit must not pass IsFrame")
	}
	if !IsFrame(fixture(t, "lcg_l1")) {
		t.Fatal("a real frame must pass IsFrame")
	}
	if !HasMagic(fixture(t, "lcg_l1")) {
		t.Fatal("HasMagic missed a real frame")
	}
	if HasMagic([]byte{0x28, 0xB5}) {
		t.Fatal("HasMagic accepted a two-byte buffer")
	}
}

func TestSkippableFrameHeader(t *testing.T) {
	h, err := ReadHeader(mustHex(t, "502a4d1804000000deadbeef"))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !h.Skippable {
		t.Fatal("want Skippable")
	}
	if h.SkippableSize != 4 {
		t.Fatalf("SkippableSize = %d, want 4", h.SkippableSize)
	}
	if h.TotalSize() != 12 {
		t.Fatalf("TotalSize = %d, want 12", h.TotalSize())
	}
	// A stream of nothing but skippable frames has no content, and reporting
	// success with an empty result would be misleading.
	if _, err := Decompress(mustHex(t, "502a4d1804000000deadbeef")); !errors.Is(err, ErrMagic) {
		t.Fatalf("skippable-only stream: want ErrMagic, got %v", err)
	}
}

func TestTrailingGarbageIsIgnored(t *testing.T) {
	// Embedded frames are routinely followed by padding or an unrelated tail.
	blob := append(append([]byte(nil), fixture(t, "lcg_l19")...), []byte("trailing junk")...)
	got, err := Decompress(blob)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, corpusFor(t, "lcg")) {
		t.Fatal("trailing bytes changed the result")
	}
}

// ── internals ────────────────────────────────────────────────────────────

// TestXXH64KnownVectors checks the checksum against constants published with
// xxHash itself, so a mistake here cannot be masked by a matching mistake in
// the frame decoder.
func TestXXH64KnownVectors(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
	}{
		{[]byte(""), 0xef46db3751d8e999},
		{[]byte("a"), 0xd24ec4f1a98c6e5b},
		{[]byte("abc"), 0x44bc2cf5ad770999},
		{[]byte("hello"), 0x26c7827d889f6da3},
		{bytes.Repeat([]byte("ABCDEFGH"), 8), 0x7a09d11da2ba464e},
	}
	for _, c := range cases {
		if got := xxh64(c.in); got != c.want {
			t.Errorf("xxh64(%d bytes) = %016x, want %016x", len(c.in), got, c.want)
		}
	}
}

func TestBitReaderRejectsMissingEndMarker(t *testing.T) {
	if _, err := newBitReader(nil); !errors.Is(err, ErrTruncated) {
		t.Fatalf("empty bitstream: got %v", err)
	}
	// The final byte carries the end marker in its highest set bit, so a zero
	// final byte is undecodable by definition.
	if _, err := newBitReader([]byte{0x12, 0x00}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("zero final byte: got %v", err)
	}
	// 0x81 is marker plus seven data bits.
	br, err := newBitReader([]byte{0x81})
	if err != nil {
		t.Fatalf("newBitReader: %v", err)
	}
	if br.remaining() != 7 {
		t.Fatalf("remaining = %d, want 7", br.remaining())
	}
	if got := br.read(7); got != 1 {
		t.Fatalf("read(7) = %d, want 1", got)
	}
	if br.overrun() {
		t.Fatal("reading exactly the available bits is not an overrun")
	}
	br.read(1)
	if !br.overrun() {
		t.Fatal("reading past the start should register as an overrun")
	}
}

func TestPredefinedTablesBuild(t *testing.T) {
	if predefErr != nil {
		t.Fatalf("predefined tables failed to build: %v", predefErr)
	}
	for _, c := range []struct {
		name string
		t    *seqTable
		log  uint8
	}{
		{"literal length", predefLL, llDefaultLog},
		{"match length", predefML, mlDefaultLog},
		{"offset", predefOF, ofDefaultLog},
	} {
		if c.t == nil {
			t.Fatalf("%s table is nil", c.name)
		}
		if c.t.log != c.log {
			t.Errorf("%s log = %d, want %d", c.name, c.t.log, c.log)
		}
		size := 1 << uint(c.log)
		if len(c.t.base) != size || len(c.t.nbits) != size || len(c.t.next) != size {
			t.Errorf("%s table is not %d slots wide", c.name, size)
		}
	}
}

// TestOffsetBaselineFollowsFormula pins the one table most easily got wrong:
// the baselines are pre-reduced by three so that codes above three need no
// further arithmetic, which makes entries 0 and 1 look like typos.
func TestOffsetBaselineFollowsFormula(t *testing.T) {
	if ofBase[0] != 0 || ofBase[1] != 1 || ofBase[2] != 1 || ofBase[3] != 5 {
		t.Fatalf("low offset baselines are %v", ofBase[:4])
	}
	for n := 2; n <= maxOff; n++ {
		if want := uint32(1)<<uint(n) - 3; ofBase[n] != want {
			t.Errorf("ofBase[%d] = %#x, want %#x", n, ofBase[n], want)
		}
		if int(ofBits[n]) != n {
			t.Errorf("ofBits[%d] = %d, want %d", n, ofBits[n], n)
		}
	}
	// The first sixteen literal length codes and the first thirty-two match
	// length codes are the value itself, offset by the shortest legal match.
	for i := 0; i < 16; i++ {
		if llBase[i] != uint32(i) {
			t.Errorf("llBase[%d] = %d, want %d", i, llBase[i], i)
		}
	}
	for i := 0; i < 32; i++ {
		if mlBase[i] != uint32(i+3) {
			t.Errorf("mlBase[%d] = %d, want %d", i, mlBase[i], i+3)
		}
	}
}

func TestExtendReusesCapacity(t *testing.T) {
	b := make([]byte, 4, 64)
	grown := extend(b, 10)
	if len(grown) != 14 {
		t.Fatalf("len = %d, want 14", len(grown))
	}
	if cap(grown) != 64 {
		t.Fatalf("cap = %d; spare capacity should have been reused", cap(grown))
	}
	tight := make([]byte, 4, 4)
	if got := extend(tight, 10); len(got) != 14 || cap(got) < 14 {
		t.Fatalf("len %d cap %d, want at least 14 of each", len(got), cap(got))
	}
}
