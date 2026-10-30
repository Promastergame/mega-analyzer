package imageforensics

import (
	"testing"
)

// minimalGIF returns a tiny valid GIF87a/GIF89a stream:
//   - 6-byte signature
//   - Logical Screen Descriptor (7 bytes)
//   - Packed = 0 → no global color table
//   - Trailer 0x3B
func minimalGIF(version string, w, h int, packed byte, tail []byte) []byte {
	out := []byte(version)
	out = append(out, byte(w&0xff), byte(w>>8), byte(h&0xff), byte(h>>8), packed, 0, 0)
	out = append(out, tail...)
	return out
}

func TestParseGIFTrailerOnly(t *testing.T) {
	g := ParseGIF(minimalGIF("GIF89a", 100, 50, 0, []byte{0x3B}))
	if !g.Valid {
		t.Fatal("expected Valid=true")
	}
	if g.Width != 100 || g.Height != 50 {
		t.Errorf("dims = %dx%d, want 100x50", g.Width, g.Height)
	}
	if g.TrailerOffset == 0 {
		t.Error("TrailerOffset should be > 0")
	}
}

func TestParseGIFRejectsShort(t *testing.T) {
	if g := ParseGIF([]byte{0x47}); g.Valid {
		t.Error("short input must not be Valid")
	}
}

func TestParseGIFRejectsBadMagic(t *testing.T) {
	if g := ParseGIF(append([]byte("NOTAGIF7"), make([]byte, 64)...)); g.Valid {
		t.Error("bad magic must not be Valid")
	}
}

func TestParseGIFTrailingData(t *testing.T) {
	tail := append([]byte{0x3B}, []byte("APPENDED")...)
	g := ParseGIF(minimalGIF("GIF87a", 1, 1, 0, tail))
	if !g.Valid {
		t.Fatal("expected Valid=true")
	}
	if string(g.TrailingData) != "APPENDED" {
		t.Errorf("TrailingData = %q, want APPENDED", g.TrailingData)
	}
}

func TestParseGIFGlobalColorTable(t *testing.T) {
	// Packed 0x80 → GCT present, size 0 → 2 entries × 3 bytes = 6 bytes.
	gct := make([]byte, 6)
	tail := append(gct, 0x3B)
	g := ParseGIF(minimalGIF("GIF89a", 1, 1, 0x80, tail))
	if !g.Valid {
		t.Fatal("expected Valid=true with GCT")
	}
}

func TestParseGIFCommentExtensionSmall(t *testing.T) {
	// Extension introducer 0x21, comment label 0xFE, sub-block size 4, data, terminator 0, then trailer.
	body := []byte{0x21, 0xFE, 4, 'a', 'b', 'c', 'd', 0, 0x3B}
	g := ParseGIF(minimalGIF("GIF89a", 1, 1, 0, body))
	if g.SuspiciousComment {
		t.Error("small comment should not be flagged suspicious")
	}
}

func TestParseGIFCommentExtensionLarge(t *testing.T) {
	// Construct a comment block of 2 sub-blocks: 255 + 255 + 600 → > 1024.
	// GIF sub-block max size is 255, so multiple chunks chain via length-prefixed format.
	body := []byte{0x21, 0xFE}
	for i := 0; i < 5; i++ {
		body = append(body, 255)
		body = append(body, make([]byte, 255)...)
	}
	body = append(body, 0, 0x3B) // terminator + trailer
	g := ParseGIF(minimalGIF("GIF89a", 1, 1, 0, body))
	if !g.SuspiciousComment {
		t.Errorf("expected SuspiciousComment for >1024 byte comment")
	}
}

func TestParseGIFOtherExtension(t *testing.T) {
	// Graphic Control Extension (label 0xF9): 4 bytes data + terminator.
	body := []byte{0x21, 0xF9, 4, 0, 0, 0, 0, 0, 0x3B}
	g := ParseGIF(minimalGIF("GIF89a", 1, 1, 0, body))
	if !g.Valid {
		t.Error("GCE-bearing GIF must remain Valid")
	}
}

func TestParseGIFImageDescriptor(t *testing.T) {
	// Image descriptor starts with 0x2C, 9 bytes of metadata, packed byte
	// (no LCT), LZW min-code-size, sub-block (1 byte) + terminator + trailer.
	body := []byte{0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0 /* lzw */, 8, 1, 0, 0, 0x3B}
	g := ParseGIF(minimalGIF("GIF89a", 1, 1, 0, body))
	if !g.Valid {
		t.Error("ID-bearing GIF must remain Valid")
	}
}

func TestParseGIFUnknownBlockBails(t *testing.T) {
	// 0x99 is an unknown block introducer.
	body := []byte{0x99, 0x3B}
	g := ParseGIF(minimalGIF("GIF89a", 1, 1, 0, body))
	if !g.Valid {
		t.Error("magic must still be honoured even when block walker bails")
	}
	if g.TrailerOffset != 0 {
		t.Error("unknown block bail must NOT advance trailer offset")
	}
}
