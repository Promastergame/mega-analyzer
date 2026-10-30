package axml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

const maxPlainManifestBytes = 16 << 20

// DecodePlainXML parses an apktool/source-tree AndroidManifest.xml through the
// same structured mapper used by the binary AXML decoder. Keeping both paths on
// one mapper prevents semantic drift between APK and extracted-directory scans.
func decodePlainXML(data []byte) (*Manifest, error) {
	if len(data) == 0 {
		return nil, errors.New("manifest XML is empty")
	}
	if len(data) > maxPlainManifestBytes {
		return nil, fmt.Errorf("manifest XML exceeds %d byte limit", maxPlainManifestBytes)
	}
	manifest := &Manifest{MetaData: make(map[string]string), XMLBytes: append([]byte(nil), data...)}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	mapper := &Decoder{}
	var currentComponent *Component
	var currentList *[]Component
	var inFilter bool
	var currentFilter *IntentFilter
	depth := 0
	seenManifest := false

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode plaintext manifest: %w", err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			if depth > maxNestingDepth {
				return nil, fmt.Errorf("manifest nesting exceeds %d", maxNestingDepth)
			}
			if len(element.Attr) > maxAttributesPerNode {
				return nil, fmt.Errorf("manifest element has too many attributes: %d", len(element.Attr))
			}
			attrs := make([]parsedAttr, 0, len(element.Attr))
			for _, attr := range element.Attr {
				attrs = append(attrs, parsedAttr{Name: attr.Name.Local, Value: attr.Value})
			}
			if element.Name.Local == "manifest" {
				seenManifest = true
			}
			mapper.applyAttrsToManifest(element.Name.Local, attrs, manifest, &currentComponent, &currentList, &inFilter, &currentFilter)
		case xml.EndElement:
			mapper.finalizeElement(element.Name.Local, manifest, &currentComponent, &currentList, &inFilter, &currentFilter)
			depth--
			if depth < 0 {
				return nil, errors.New("invalid manifest element nesting")
			}
		}
	}
	if !seenManifest {
		return nil, errors.New("XML does not contain a manifest root element")
	}
	if depth != 0 {
		return nil, errors.New("manifest XML ended with unclosed elements")
	}
	return manifest, nil
}
