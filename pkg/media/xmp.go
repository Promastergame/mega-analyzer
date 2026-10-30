package media

import (
	"encoding/xml"
	"io"
	"strings"
)

// ─── XMP extraction ──────────────────────────────────────────────────────────
//
// XMP (Extensible Metadata Platform) is Adobe's RDF/XML metadata format,
// carried in JPEG as a second APP1 segment prefixed by the XMP namespace URI,
// and in PNG as an iTXt chunk with keyword "XML:com.adobe.xmp" (see
// pngchunks.go). Producers vary wildly in namespace prefixes, so fields are
// matched by local element name rather than fully-qualified name.

const xmpAPP1Prefix = "http://ns.adobe.com/xap/1.0/\x00"

// findJPEGXMP walks JPEG markers looking for an APP1 segment carrying an XMP
// packet and returns the raw XML payload that follows the namespace prefix
// (nil if absent). A separate walk from findJPEGExifTIFF (same marker-skip
// shape, different APP1 payload prefix) - kept independent so each function
// stays single-purpose, matching how findJPEGExifTIFF/findJPEGDimensions are
// already two separate walks in this package.
func findJPEGXMP(data []byte) []byte {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil
	}
	pos := 2
	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			break
		}
		marker := data[pos+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD9) {
			pos += 2
			continue
		}
		if marker == 0xDA {
			break
		}
		segLen := int(data[pos+2])<<8 | int(data[pos+3])
		if segLen < 2 || pos+2+segLen > len(data) {
			break
		}
		if marker == 0xE1 {
			seg := data[pos+4 : pos+2+segLen]
			if len(seg) >= len(xmpAPP1Prefix) && string(seg[0:len(xmpAPP1Prefix)]) == xmpAPP1Prefix {
				return seg[len(xmpAPP1Prefix):]
			}
		}
		pos += 2 + segLen
	}
	return nil
}

// xmpFieldNames lists the XMP/RDF leaf element local-names this tool
// recognizes and surfaces. Matched by local name only (namespace prefix
// ignored) since dc:/xmp:/tiff:/exif:/photoshop: prefixes vary by producer.
var xmpFieldNames = map[string]string{
	"CreatorTool":  "CreatorTool",
	"Rating":       "Rating",
	"Label":        "Label",
	"subject":      "Subject",
	"title":        "Title",
	"description":  "Description",
	"creator":      "Creator",
	"GPSLatitude":  "GPSLatitude",
	"GPSLongitude": "GPSLongitude",
	"DateCreated":  "DateCreated",
	"ModifyDate":   "ModifyDate",
	"CreateDate":   "CreateDate",
}

const maxXMPFields = 32

// parseXMP extracts a bounded set of well-known fields from a raw XMP/RDF
// XML packet using a streaming token decoder (not a full RDF model - XMP's
// bag/seq/alt list constructs are flattened to comma-joined text, which is
// sufficient for a "here's what a photo says about itself" forensic view).
// Wrapped in its own recover: parsing adversarial XML is new attack surface
// for this package and must never take down the analysis pipeline.
func parseXMP(raw []byte) (fields map[string]string, ok bool) {
	fields = make(map[string]string)
	defer func() {
		if recover() != nil {
			fields = map[string]string{}
			ok = false
		}
	}()

	if len(raw) == 0 {
		return fields, false
	}

	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	var curName string
	var curText strings.Builder
	found := false

	for {
		if len(fields) >= maxXMPFields {
			break
		}
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}
		switch el := tok.(type) {
		case xml.StartElement:
			localName := localXMLName(el.Name.Local)
			if display, known := xmpFieldNames[localName]; known {
				curName = display
				curText.Reset()
			} else {
				curName = ""
			}
		case xml.CharData:
			if curName != "" {
				curText.Write(el)
			}
		case xml.EndElement:
			if curName != "" {
				text := strings.TrimSpace(curText.String())
				if text != "" {
					if existing, has := fields[curName]; has {
						fields[curName] = existing + ", " + text
					} else {
						fields[curName] = text
					}
					found = true
				}
				curName = ""
				curText.Reset()
			}
		}
	}

	return fields, found
}

// localXMLName strips a namespace prefix ("dc:title" -> "title") since XMP
// producers vary in which prefix they bind to a given namespace URI.
func localXMLName(name string) string {
	if idx := strings.Index(name, ":"); idx != -1 {
		return name[idx+1:]
	}
	return name
}

// capXMPRaw truncates a raw XMP packet for storage/display so a file
// embedding a pathologically large XMP blob can't bloat the report.
func capXMPRaw(raw []byte) string {
	if len(raw) <= xmpRawCap {
		return string(raw)
	}
	return string(raw[:xmpRawCap]) + "... (truncated)"
}
