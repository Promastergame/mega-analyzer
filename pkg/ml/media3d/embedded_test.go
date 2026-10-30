package media3d

import (
	"encoding/base64"
	"strings"
	"testing"
)

// pngSig is the 8-byte PNG signature, used as a stand-in payload throughout.
const pngSig = "\x89PNG\r\n\x1a\n"

// glbWithJSON builds a two-chunk GLB from a JSON document and an optional BIN
// payload. It reuses buildGLB/pad4/rawChunk from media3d_test.go rather than
// duplicating the container writer, so a change to the header layout is caught
// in one place instead of drifting between two test files.
func glbWithJSON(doc string, bin []byte) []byte {
	chunks := []rawChunk{{tag: "JSON", data: pad4([]byte(doc), ' ')}}
	if bin != nil {
		chunks = append(chunks, rawChunk{tag: "BIN", data: pad4(bin, 0)})
	}
	return buildGLB(2, chunks...)
}

func TestSniffImageMimeCoversTheShippedCodecs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"png", pngSig, "image/png"},
		{"jpeg", "\xff\xd8\xff\xe0", "image/jpeg"},
		{"webp", "RIFF\x00\x00\x00\x00WEBP", "image/webp"},
		{"gif87", "GIF87a", "image/gif"},
		{"gif89", "GIF89a", "image/gif"},
		{"ktx2", "\xabKTX 20\xbb\r\n\x1a\n", "image/ktx2"},
		{"dds", "DDS ", "image/vnd-ms.dds"},
		{"qoi", "qoif", "image/qoi"},
		{"unknown", "NOPE", ""},
		{"empty", "", ""},
		// A one-byte buffer must not index past the end of the slice.
		{"truncated png", "\x89", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sniffImageMime([]byte(tc.in)); got != tc.want {
				t.Fatalf("sniffImageMime(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDataURIAcceptsBothBase64Alphabets(t *testing.T) {
	payload := []byte(pngSig)
	std := "data:image/png;base64," + base64.StdEncoding.EncodeToString(payload)
	raw, mime, ok := decodeDataURI(std)
	if !ok || string(raw) != pngSig || mime != "image/png" {
		t.Fatalf("standard alphabet: ok=%v mime=%q raw=%q", ok, mime, raw)
	}

	// 0xFB 0xFF 0xBF encodes as "+/+/" in the standard alphabet and "-_-_" in
	// the URL-safe one. The URL-safe form is invalid standard base64, so this
	// exercises the fallback branch rather than the happy path twice.
	urlSafe := "data:image/png;base64,-_-_"
	raw, _, ok = decodeDataURI(urlSafe)
	if !ok {
		t.Fatalf("url-safe alphabet was rejected")
	}
	if len(raw) != 3 || raw[0] != 0xFB || raw[1] != 0xFF || raw[2] != 0xBF {
		t.Fatalf("url-safe decode = % x, want fb ff bf", raw)
	}

	// Uppercase ";BASE64" is legal per RFC 2397 and must be honoured.
	if _, _, ok := decodeDataURI("data:image/png;BASE64," + base64.StdEncoding.EncodeToString(payload)); !ok {
		t.Fatalf("uppercase base64 marker was rejected")
	}
}

func TestDataURIRejectsWhatItCannotDecode(t *testing.T) {
	// Percent-encoded data URIs are legal but never observed on glTF images;
	// decoding them as base64 would hand back silent garbage.
	if _, mime, ok := decodeDataURI("data:image/png,%89PNG"); ok || mime != "image/png" {
		t.Fatalf("percent-encoded URI: ok=%v mime=%q, want false/image/png", ok, mime)
	}
	if _, _, ok := decodeDataURI("https://example.com/tex.png"); ok {
		t.Fatalf("plain http URI decoded as a data URI")
	}
	if _, _, ok := decodeDataURI("data:image/png;base64"); ok {
		t.Fatalf("URI with no comma decoded")
	}
	if _, _, ok := decodeDataURI("data:image/png;base64,!!!not base64!!!"); ok {
		t.Fatalf("invalid base64 decoded")
	}
}

func TestShortURIKeepsReportsReadable(t *testing.T) {
	short := strings.Repeat("a", 64)
	if got := shortURI(short); got != short {
		t.Fatalf("a 64-char URI was truncated")
	}
	long := strings.Repeat("a", 500)
	got := shortURI(long)
	if len(got) != 67 || !strings.HasSuffix(got, "...") {
		t.Fatalf("shortURI len = %d (%q...), want 67 ending in ...", len(got), got[:10])
	}
}

func TestBufferViewAtRejectsMalformedEntries(t *testing.T) {
	doc, err := ParseDocument([]byte(`{"asset":{"version":"2.0"},"bufferViews":[
		{"buffer":0,"byteOffset":16,"byteLength":4,"byteStride":12},
		{"buffer":0,"byteLength":0},
		{"buffer":-1,"byteLength":8},
		{"nonsense":true}
	]}`))
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}

	bv, ok := doc.BufferViewAt(0)
	if !ok {
		t.Fatalf("a well-formed bufferView was rejected")
	}
	if bv.ByteOffset != 16 || bv.ByteLength != 4 || bv.ByteStride != 12 {
		t.Fatalf("BufferViewAt(0) = %+v", bv)
	}

	// Zero length, a negative buffer index and a view with no byteLength at
	// all are all unusable, and must report so rather than yield a zero value
	// the caller would then slice with.
	for _, i := range []int{1, 2, 3, -1, 99} {
		if _, ok := doc.BufferViewAt(i); ok {
			t.Fatalf("BufferViewAt(%d) accepted an unusable entry", i)
		}
	}

	var nilDoc *Document
	if _, ok := nilDoc.BufferViewAt(0); ok {
		t.Fatalf("a nil Document returned a bufferView")
	}
}

func TestEmbeddedImagesResolvesBufferViewIntoBIN(t *testing.T) {
	glb := glbWithJSON(`{"asset":{"version":"2.0"},
		"images":[{"bufferView":0,"mimeType":"image/png"}],
		"bufferViews":[{"buffer":0,"byteOffset":0,"byteLength":8}]}`, []byte(pngSig))

	imgs := ExtractImages(glb)
	if len(imgs) != 1 {
		t.Fatalf("got %d images, want 1", len(imgs))
	}
	got := imgs[0]
	if got.Source != "bufferView" {
		t.Fatalf("Source = %q, want bufferView", got.Source)
	}
	if got.Offset != 0 || got.Length != 8 {
		t.Fatalf("Offset/Length = %d/%d, want 0/8", got.Offset, got.Length)
	}
	if string(got.Data) != pngSig {
		t.Fatalf("payload = % x, want the PNG signature", got.Data)
	}
	if got.MimeType != "image/png" {
		t.Fatalf("MimeType = %q", got.MimeType)
	}
	if got.Note != "" {
		t.Fatalf("a fully resolved image carried a note: %q", got.Note)
	}
}

func TestEmbeddedImagesTrustsTheBytesOverTheLabel(t *testing.T) {
	// Exporters mislabel textures constantly. The sniffed type wins, and the
	// disagreement is recorded rather than swallowed.
	glb := glbWithJSON(`{"asset":{"version":"2.0"},
		"images":[{"bufferView":0,"mimeType":"image/jpeg"}],
		"bufferViews":[{"buffer":0,"byteOffset":0,"byteLength":8}]}`, []byte(pngSig))

	imgs := ExtractImages(glb)
	if len(imgs) != 1 {
		t.Fatalf("got %d images, want 1", len(imgs))
	}
	if imgs[0].MimeType != "image/png" {
		t.Fatalf("MimeType = %q, want the sniffed image/png", imgs[0].MimeType)
	}
	if !strings.Contains(imgs[0].Note, "declared image/jpeg") {
		t.Fatalf("Note = %q, want it to record the mismatch", imgs[0].Note)
	}
}

func TestEmbeddedImagesExplainsEveryUnreachableTexture(t *testing.T) {
	cases := []struct {
		name     string
		doc      string
		bin      []byte
		wantNote string
	}{
		{
			name:     "index out of range",
			doc:      `{"asset":{"version":"2.0"},"images":[{"bufferView":9}],"bufferViews":[{"buffer":0,"byteLength":8}]}`,
			bin:      []byte(pngSig),
			wantNote: "out of range",
		},
		{
			name:     "external buffer",
			doc:      `{"asset":{"version":"2.0"},"images":[{"bufferView":0}],"bufferViews":[{"buffer":1,"byteLength":8}]}`,
			bin:      []byte(pngSig),
			wantNote: "external buffer",
		},
		{
			name:     "runs past the BIN chunk",
			doc:      `{"asset":{"version":"2.0"},"images":[{"bufferView":0}],"bufferViews":[{"buffer":0,"byteOffset":0,"byteLength":4096}]}`,
			bin:      []byte(pngSig),
			wantNote: "past the end",
		},
		{
			name:     "no BIN chunk at all",
			doc:      `{"asset":{"version":"2.0"},"images":[{"bufferView":0}],"bufferViews":[{"buffer":0,"byteOffset":0,"byteLength":8}]}`,
			bin:      nil,
			wantNote: "no BIN chunk",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			imgs := ExtractImages(glbWithJSON(tc.doc, tc.bin))
			if len(imgs) != 1 {
				t.Fatalf("got %d images, want 1", len(imgs))
			}
			if imgs[0].Data != nil {
				t.Fatalf("unreachable texture still produced %d bytes", len(imgs[0].Data))
			}
			if !strings.Contains(imgs[0].Note, tc.wantNote) {
				t.Fatalf("Note = %q, want it to mention %q", imgs[0].Note, tc.wantNote)
			}
		})
	}
}

func TestEmbeddedImagesHandlesDataURIsAndExternalFiles(t *testing.T) {
	inline := base64.StdEncoding.EncodeToString([]byte(pngSig))
	doc := `{"asset":{"version":"2.0"},"images":[
		{"uri":"data:image/png;base64,` + inline + `"},
		{"uri":"textures/hero.png"},
		{"uri":"data:image/png,notbase64"},
		{}
	]}`

	// A bare .gltf document, not a GLB: this is the path that proves the
	// extractor does not require a container.
	imgs := ExtractImages([]byte(doc))
	if len(imgs) != 4 {
		t.Fatalf("got %d images, want 4", len(imgs))
	}

	if imgs[0].Source != "data-uri" || string(imgs[0].Data) != pngSig {
		t.Fatalf("inline image: source=%q len=%d", imgs[0].Source, len(imgs[0].Data))
	}
	if imgs[0].MimeType != "image/png" {
		t.Fatalf("inline image mime = %q", imgs[0].MimeType)
	}

	if imgs[1].Source != "external" || imgs[1].Data != nil {
		t.Fatalf("sibling file: source=%q data=%v", imgs[1].Source, imgs[1].Data)
	}
	if !strings.Contains(imgs[1].Note, "separate file") {
		t.Fatalf("sibling file note = %q", imgs[1].Note)
	}

	if imgs[2].Source != "data-uri" || imgs[2].Data != nil {
		t.Fatalf("non-base64 URI produced data")
	}
	if !strings.Contains(imgs[2].Note, "not base64") {
		t.Fatalf("non-base64 note = %q", imgs[2].Note)
	}

	if imgs[3].Source != "external" || !strings.Contains(imgs[3].Note, "neither uri nor bufferView") {
		t.Fatalf("empty image entry: source=%q note=%q", imgs[3].Source, imgs[3].Note)
	}
}

func TestEmbeddedImagesTruncatesLongDataURIsInTheReport(t *testing.T) {
	inline := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 300)))
	doc := `{"asset":{"version":"2.0"},"images":[{"uri":"data:image/png;base64,` + inline + `"}]}`
	imgs := ExtractImages([]byte(doc))
	if len(imgs) != 1 {
		t.Fatalf("got %d images, want 1", len(imgs))
	}
	// The payload is still fully decoded; only the reported URI is clipped.
	if len(imgs[0].Data) != 300 {
		t.Fatalf("payload len = %d, want 300", len(imgs[0].Data))
	}
	if !strings.HasSuffix(imgs[0].URI, "...") {
		t.Fatalf("URI was not truncated: len=%d", len(imgs[0].URI))
	}
}

func TestExtractImagesIsNilOnRubbish(t *testing.T) {
	cases := map[string][]byte{
		"nil":             nil,
		"empty":           {},
		"random":          []byte("this is not a model at all"),
		"truncated glb":   []byte("glTF\x02\x00"),
		"glb with no json": buildGLB(2, rawChunk{tag: "BIN", data: []byte(pngSig)}),
		"broken json":     glbWithJSON(`{"asset":`, nil),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ExtractImages(in); got != nil {
				t.Fatalf("ExtractImages returned %d images, want nil", len(got))
			}
		})
	}
}

func TestEmbeddedImagesOnADocumentWithNoImages(t *testing.T) {
	doc, err := ParseDocument(minimalDoc())
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if got := doc.EmbeddedImages(nil); len(got) != 0 {
		t.Fatalf("got %d images from a document with none", len(got))
	}

	var nilDoc *Document
	if got := nilDoc.EmbeddedImages(nil); got != nil {
		t.Fatalf("a nil Document produced images")
	}
}
