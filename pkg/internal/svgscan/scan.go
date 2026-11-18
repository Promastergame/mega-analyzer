// Package svgscan inspects untrusted SVG without rendering it or resolving
// external entities. Findings describe content, not proof of execution.
package svgscan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"strings"
)

const MaxBytes = 8 << 20
const maxFindings = 100
const maxEncodedBytes = 1 << 20

type Finding struct {
	Rule, Description, Evidence, Severity string
	Offset                                int
}

type Result struct {
	Findings []Finding
	Complete bool
}

func (r Result) Active() bool {
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Rule, "svg.active.") {
			return true
		}
	}
	return false
}

func Scan(data []byte) Result {
	r := Result{Complete: true}
	if len(data) > MaxBytes {
		data = data[:MaxBytes]
		r.Complete = false
	}
	seen := make(map[string]bool)
	add := func(rule, description, evidence, severity string, offset int) {
		key := rule + "\x00" + evidence
		if seen[key] {
			return
		}
		if len(r.Findings) >= maxFindings {
			r.Complete = false
			return
		}
		seen[key] = true
		if len(evidence) > 160 {
			evidence = evidence[:160] + "..."
		}
		r.Findings = append(r.Findings, Finding{rule, description, evidence, severity, offset})
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	// RawToken accepts XML fragments, namespace prefixes and mismatched HTML
	// end tags. Strict=false also preserves unknown entities; no entity fetches.
	decoder.Strict = false
	var stack []string
	for {
		offset := int(decoder.InputOffset())
		token, err := decoder.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			r.Complete = false
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if len(stack) >= 256 {
				r.Complete = false
				return r
			}
			stack = append(stack, name)
			switch name {
			case "script":
				add("svg.active.script", "SVG contains a script element; execution depends on its embedding context", "<script>", "high", offset)
			case "foreignobject":
				add("svg.active.foreign_object", "SVG embeds HTML through foreignObject", "<foreignObject>", "medium", offset)
			}
			animation := name == "animate" || name == "set" || name == "animatetransform" || name == "animatemotion"
			linkAnimation := false
			for _, a := range t.Attr {
				if strings.EqualFold(a.Name.Local, "attributeName") {
					linkAnimation = strings.EqualFold(strings.TrimSpace(a.Value), "href") || strings.EqualFold(strings.TrimSpace(a.Value), "xlink:href")
				}
			}
			for _, a := range t.Attr {
				attr := strings.ToLower(a.Name.Local)
				// xmlns declarations and editor namespace URIs are inert.
				if a.Name.Space == "xmlns" || attr == "xmlns" {
					continue
				}
				if isEvent(attr) && strings.TrimSpace(a.Value) != "" {
					add("svg.active.event", "SVG contains a JavaScript event handler", attr+"="+a.Value, "high", offset)
				}
				if attr == "href" || attr == "src" {
					if dangerousURI(a.Value) {
						add("svg.active.uri", "SVG reference uses an executable URI scheme", attr+"="+a.Value, "high", offset)
					}
				}
				if animation && linkAnimation && (attr == "values" || attr == "from" || attr == "to" || attr == "by") {
					for _, value := range strings.Split(a.Value, ";") {
						if dangerousURI(value) {
							add("svg.active.animation_uri", "SVG animation changes a reference to an executable URI", attr+"="+a.Value, "high", offset)
							break
						}
					}
				}
				if name == "path" && attr == "d" {
					inspectEncoded(a.Value, "path coordinates", offset, add)
				}
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.Comment:
			inspectEncoded(string(t), "comment", offset, add)
		case xml.CharData:
			for _, parent := range stack {
				if parent == "metadata" || parent == "desc" {
					inspectEncoded(string(t), parent, offset, add)
					break
				}
			}
		}
	}
	if len(stack) != 0 {
		r.Complete = false
	}
	return r
}

func isEvent(name string) bool {
	if len(name) < 3 || !strings.HasPrefix(name, "on") {
		return false
	}
	for _, c := range name[2:] {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func dangerousURI(value string) bool {
	value = strings.ToLower(strings.Map(func(r rune) rune {
		if r <= 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value))
	if strings.HasPrefix(value, "javascript:") || strings.HasPrefix(value, "vbscript:") {
		return true
	}
	if !strings.HasPrefix(value, "data:") {
		return false
	}
	media := strings.TrimPrefix(value, "data:")
	if idx := strings.IndexAny(media, ";,"); idx >= 0 {
		media = media[:idx]
	}
	switch media {
	case "text/html", "application/xhtml+xml", "application/javascript", "text/javascript", "application/ecmascript", "text/ecmascript", "image/svg+xml":
		return true
	}
	return false
}

func entropy(s string) float64 {
	var counts [256]int
	for i := range s {
		counts[s[i]]++
	}
	var h float64
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

func inspectEncoded(text, source string, offset int, add func(string, string, string, string, int)) {
	// Whitespace wrapping is common in metadata/comment payloads. Numeric
	// coordinate streams and ordinary XML metadata do not meet the entropy gate.
	compact := strings.Join(strings.Fields(text), "")
	for start := 0; start < len(compact); {
		for start < len(compact) && !base64Byte(compact[start]) {
			start++
		}
		end := start
		for end < len(compact) && base64Byte(compact[end]) {
			end++
		}
		if end-start >= 256 {
			candidate := compact[start:end]
			if len(candidate) > maxEncodedBytes {
				candidate = candidate[:maxEncodedBytes]
			}
			h := entropy(candidate)
			var decoded []byte
			if h >= 4.5 {
				decoded, _ = base64.StdEncoding.DecodeString(candidate)
				if len(decoded) == 0 {
					decoded, _ = base64.RawStdEncoding.DecodeString(candidate)
				}
				if len(decoded) == 0 {
					decoded, _ = base64.RawURLEncoding.DecodeString(candidate)
				}
			} else if h >= 3.2 && len(candidate) >= 512 {
				decoded, _ = hex.DecodeString(candidate)
			}
			if len(decoded) > 0 {
				format := payloadFormat(decoded)
				if format != "" {
					add("svg.embedded_payload", "SVG contains an encoded executable or archive signature; verify the decoded payload", fmt.Sprintf("%s: %s (%d decoded bytes)", source, format, len(decoded)), "high", offset)
				} else {
					add("svg.encoded_data", "SVG contains long encoded data; entropy alone does not prove malware or a C2 configuration", fmt.Sprintf("%s: %d encoded bytes, entropy %.2f", source, end-start, h), "low", offset)
				}
			}
		}
		start = end + 1
	}
}

func base64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '=' || b == '_' || b == '-'
}

func payloadFormat(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("dex\n")):
		return "DEX"
	case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF"
	case bytes.HasPrefix(data, []byte("MZ")):
		return "PE"
	case bytes.HasPrefix(data, []byte{'P', 'K', 3, 4}):
		return "ZIP"
	}
	return ""
}
