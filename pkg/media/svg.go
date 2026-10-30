package media

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
)

// ─── SVG ──────────────────────────────────────────────────────────────────
//
// SVG is XML/text, not binary - no fixed magic number, dimensions live in
// root-element attributes rather than a fixed header. This also doubles as
// a lightweight security check: SVG embedding <script> or on*= event-handler
// attributes is a known stored-XSS vector, worth flagging in a forensics tool.

// maxSVGScanBytes bounds how much of a (potentially huge or malformed) SVG
// document this scans, to keep cost bounded.
const maxSVGScanBytes = 256 * 1024

var svgScriptTagRe = regexp.MustCompile(`(?i)<script[\s>]`)
var svgEventAttrRe = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)

// parseSVGInfo extracts root <svg> width/height/viewBox and flags any
// embedded <script> tags or on*= event-handler attributes. Recover-wrapped:
// XML decoding of arbitrary/hostile SVG input must never panic the pipeline.
func parseSVGInfo(data []byte) (result map[string]string) {
	result = make(map[string]string)
	defer func() {
		if recover() != nil {
			result = map[string]string{}
		}
	}()

	scan := data
	if len(scan) > maxSVGScanBytes {
		scan = scan[:maxSVGScanBytes]
	}

	dec := xml.NewDecoder(strings.NewReader(string(scan)))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if se, isStart := tok.(xml.StartElement); isStart {
			if localXMLName(se.Name.Local) == "svg" {
				for _, attr := range se.Attr {
					switch localXMLName(attr.Name.Local) {
					case "width":
						result["SVG_Width"] = attr.Value
					case "height":
						result["SVG_Height"] = attr.Value
					case "viewBox":
						result["SVG_ViewBox"] = attr.Value
					}
				}
				break // only need the root element's attributes
			}
		}
	}

	scriptCount := len(svgScriptTagRe.FindAllIndex(scan, -1))
	eventAttrCount := len(svgEventAttrRe.FindAllIndex(scan, -1))
	if scriptCount > 0 || eventAttrCount > 0 {
		total := scriptCount + eventAttrCount
		result["SVG_Has_Script"] = fmt.Sprintf("yes (%d occurrence(s): %d <script> tag(s), %d event-handler attribute(s)) - potential XSS/stored-script vector", total, scriptCount, eventAttrCount)
	}

	return result
}
