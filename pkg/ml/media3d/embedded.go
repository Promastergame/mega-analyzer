package media3d

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EMBEDDED TEXTURE EXTRACTION
//
// A glTF asset can carry its textures three different ways, and a tool that
// only understands one of them will report "no images" on perfectly ordinary
// files:
//
//   1. bufferView  - the bytes live inside the GLB BIN chunk. This is what
//                    every exporter produces for .glb.
//   2. data: URI   - the bytes are base64 inline in the JSON. Common for .gltf
//                    files that still want to be self-contained.
//   3. plain URI   - a sibling file on disk. Nothing to extract, but worth
//                    naming so the caller knows what is missing.
//
// Nothing here modifies Document, so the census in Counts and every existing
// caller keeps behaving exactly as before.
// ═══════════════════════════════════════════════════════════════════════════════

// EmbeddedImage is one texture recovered from a glTF asset.
type EmbeddedImage struct {
	// Index is the position in the document's images array.
	Index int
	// Source is "bufferView", "data-uri" or "external".
	Source string
	// MimeType is the declared type when present, otherwise one sniffed from
	// the payload. Empty when neither is available.
	MimeType string
	// URI is the raw uri field, truncated for data URIs.
	URI string
	// Offset and Length locate the payload inside the BIN chunk. Both are zero
	// for data URIs and external references.
	Offset int
	Length int
	// Data is the payload. Nil for external references.
	Data []byte
	// Note explains why Data is nil when it is.
	Note string
}

// BufferView is the decoded form of one bufferViews entry.
type BufferView struct {
	Buffer     int
	ByteOffset int
	ByteLength int
	ByteStride int
}

type gltfBufferView struct {
	Buffer     int `json:"buffer"`
	ByteOffset int `json:"byteOffset"`
	ByteLength int `json:"byteLength"`
	ByteStride int `json:"byteStride"`
}

// BufferViewAt decodes one bufferViews entry on demand. The array is stored as
// json.RawMessage so that an unknown or future field can never fail the whole
// document parse; the cost is this lazy second decode, paid only for the
// handful of views an image actually points at.
func (d *Document) BufferViewAt(i int) (BufferView, bool) {
	if d == nil || i < 0 || i >= len(d.BufferViews) {
		return BufferView{}, false
	}
	var bv gltfBufferView
	if err := json.Unmarshal(d.BufferViews[i], &bv); err != nil {
		return BufferView{}, false
	}
	if bv.ByteLength <= 0 || bv.ByteOffset < 0 || bv.Buffer < 0 {
		return BufferView{}, false
	}
	return BufferView(bv), true
}

// sniffImageMime identifies a payload from its first bytes. Declared mimeType
// is advisory - exporters get it wrong, and a PNG labelled image/jpeg should
// still decode as a PNG.
func sniffImageMime(b []byte) string {
	switch {
	case len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n":
		return "image/png"
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return "image/jpeg"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "image/webp"
	case len(b) >= 6 && (string(b[:6]) == "GIF87a" || string(b[:6]) == "GIF89a"):
		return "image/gif"
	case len(b) >= 12 && string(b[:12]) == "\xabKTX 20\xbb\r\n\x1a\n":
		return "image/ktx2"
	case len(b) >= 4 && string(b[:4]) == "DDS ":
		return "image/vnd-ms.dds"
	case len(b) >= 4 && string(b[:4]) == "qoif":
		return "image/qoi"
	}
	return ""
}

// decodeDataURI pulls the payload out of a data: URI. Only the base64 form is
// accepted; the percent-encoded form is legal but has never been observed on a
// glTF image and decoding it silently would risk producing garbage bytes.
func decodeDataURI(uri string) ([]byte, string, bool) {
	if !strings.HasPrefix(uri, "data:") {
		return nil, "", false
	}
	head, payload, found := strings.Cut(uri[len("data:"):], ",")
	if !found {
		return nil, "", false
	}
	mime := head
	isB64 := false
	if i := strings.LastIndex(head, ";"); i >= 0 {
		if strings.EqualFold(strings.TrimSpace(head[i+1:]), "base64") {
			isB64 = true
			mime = head[:i]
		}
	}
	if !isB64 {
		return nil, strings.TrimSpace(mime), false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		// Some producers emit the URL-safe alphabet. Try it before giving up.
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(payload))
		if err != nil {
			return nil, strings.TrimSpace(mime), false
		}
	}
	return raw, strings.TrimSpace(mime), true
}

// shortURI keeps a data URI readable in a report.
func shortURI(uri string) string {
	const limit = 64
	if len(uri) <= limit {
		return uri
	}
	return uri[:limit] + "..."
}

// EmbeddedImages resolves every image in the document against the supplied BIN
// chunk. Pass nil for bin when the document is a bare .gltf file: bufferView
// images then report as unresolvable rather than being silently dropped.
func (d *Document) EmbeddedImages(bin []byte) []EmbeddedImage {
	if d == nil {
		return nil
	}
	out := make([]EmbeddedImage, 0, len(d.Images))

	for i := range d.Images {
		src := &d.Images[i]
		img := EmbeddedImage{Index: i, MimeType: src.MimeType, URI: shortURI(src.URI)}

		switch {
		case strings.HasPrefix(src.URI, "data:"):
			img.Source = "data-uri"
			raw, mime, ok := decodeDataURI(src.URI)
			if !ok {
				img.Note = "data URI is not base64-encoded"
				break
			}
			img.Data = raw
			if img.MimeType == "" {
				img.MimeType = mime
			}

		case src.BufferView != nil:
			img.Source = "bufferView"
			bv, ok := d.BufferViewAt(*src.BufferView)
			if !ok {
				img.Note = "bufferView index is out of range or malformed"
				break
			}
			img.Offset, img.Length = bv.ByteOffset, bv.ByteLength
			if bv.Buffer != 0 {
				img.Note = "image lives in an external buffer, not the BIN chunk"
				break
			}
			// uint64 throughout: chunkLength is a uint32 and int is 32 bits on
			// arm/386, where offset+length can wrap negative and slip past a
			// naive bounds check.
			end := uint64(bv.ByteOffset) + uint64(bv.ByteLength)
			if bin == nil {
				img.Note = "no BIN chunk available to read from"
				break
			}
			if end > uint64(len(bin)) {
				img.Note = "bufferView runs past the end of the BIN chunk"
				break
			}
			img.Data = bin[bv.ByteOffset:end]

		case src.URI != "":
			img.Source = "external"
			img.Note = "texture is a separate file next to the asset"

		default:
			img.Source = "external"
			img.Note = "image entry declares neither uri nor bufferView"
		}

		if sniffed := sniffImageMime(img.Data); sniffed != "" && sniffed != img.MimeType {
			if img.MimeType == "" {
				img.MimeType = sniffed
			} else {
				img.Note = "declared " + img.MimeType + " but the bytes are " + sniffed
				img.MimeType = sniffed
			}
		}
		out = append(out, img)
	}
	return out
}

// ExtractImages is the one-call form: hand it a whole .glb or .gltf buffer and
// get back every texture it carries. Unparseable input yields nil, never an
// error - this runs over files pulled out of an APK, where malformed is normal.
func ExtractImages(data []byte) []EmbeddedImage {
	var (
		jsonPart []byte
		bin      []byte
	)

	switch {
	case IsGLB(data):
		c, err := ReadContainer(data)
		if err != nil {
			return nil
		}
		var ok bool
		if jsonPart, ok = c.JSON(); !ok {
			return nil
		}
		bin, _ = c.Find("BIN")
	case looksLikeJSON(data):
		jsonPart = data
	default:
		return nil
	}

	doc, err := ParseDocument(jsonPart)
	if err != nil {
		return nil
	}
	return doc.EmbeddedImages(bin)
}
