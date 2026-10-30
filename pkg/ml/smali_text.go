package ml

import (
	"strconv"
	"strings"
	"unicode/utf16"
)

// smaliCodeLine removes comments without truncating # inside string literals.
func smaliCodeLine(line string) string {
	quoted, escaped := false, false
	for i := 0; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		if quoted && line[i] == '\\' {
			escaped = true
			continue
		}
		if line[i] == '"' {
			quoted = !quoted
		}
		if line[i] == '#' && !quoted {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}

// smaliNonCodeState excludes annotation and switch/array payload data from
// executable instruction features. Labels and ordinary directives are handled
// separately so callers can retain physical line numbers and the original body.
type smaliNonCodeState struct {
	annotationDepth int
	payload         string
}

func (s *smaliNonCodeState) skip(line string) bool {
	canonical := strings.Join(strings.Fields(line), " ")
	if s.payload != "" {
		if canonical == ".end "+s.payload {
			s.payload = ""
		}
		return true
	}
	if hasSmaliDirective(line, ".annotation") || hasSmaliDirective(line, ".subannotation") || strings.Contains(line, "= .subannotation ") {
		s.annotationDepth++
		return true
	}
	if s.annotationDepth > 0 {
		if canonical == ".end annotation" || canonical == ".end subannotation" {
			s.annotationDepth--
		}
		return true
	}
	for _, name := range []string{"packed-switch", "sparse-switch", "array-data"} {
		if hasSmaliDirective(line, "."+name) {
			s.payload = name
			return true
		}
	}
	return false
}

func decodeSmaliLiteral(raw string) string {
	if !strings.Contains(raw, "\\") {
		return raw
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' || i+1 >= len(raw) {
			b.WriteByte(raw[i])
			continue
		}
		i++
		switch raw[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case '0':
			b.WriteByte(0)
		case '\\', '"', '\'':
			b.WriteByte(raw[i])
		case 'u':
			if i+4 < len(raw) {
				n, err := strconv.ParseUint(raw[i+1:i+5], 16, 16)
				if err == nil {
					r := rune(n)
					i += 4
					if r >= 0xd800 && r <= 0xdbff && i+6 < len(raw) && raw[i+1:i+3] == "\\u" {
						low, e := strconv.ParseUint(raw[i+3:i+7], 16, 16)
						if e == nil && low >= 0xdc00 && low <= 0xdfff {
							r = utf16.DecodeRune(r, rune(low))
							i += 6
						}
					}
					b.WriteRune(r)
					continue
				}
			}
			b.WriteString("\\u")
		default:
			b.WriteByte('\\')
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

// Smali separates directive tokens with whitespace, not necessarily one space.
func hasSmaliDirective(line, directive string) bool {
	return strings.HasPrefix(line, directive) && (len(line) == len(directive) || line[len(directive)] == ' ' || line[len(directive)] == '\t')
}
