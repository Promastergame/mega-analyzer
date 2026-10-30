package apkloader

import (
	"fmt"
	"strings"
)

// Encoded annotation values can span lines and contain nested arrays and
// subannotations. Read just the consumed lines so large classes stay linear.
type smaliValueReader struct {
	raw  []string
	line int
	text string
	pos  int
}

func parseSmaliValue(s string) (*SmaliValue, error) {
	lines := strings.Split(s, "\n")
	v, last, err := parseSmaliValueLines(lines[0], lines, 0)
	if err == nil {
		for _, line := range lines[last+1:] {
			if stripSmaliCommentFull(line) != "" {
				return nil, fmt.Errorf("unexpected text after encoded value")
			}
		}
	}
	return v, err
}

func parseSmaliValueLines(first string, raw []string, line int) (*SmaliValue, int, error) {
	r := &smaliValueReader{raw: raw, line: line, text: stripSmaliCommentFull(first)}
	v, err := r.value(0)
	if err == nil && strings.TrimSpace(r.text[r.pos:]) != "" {
		err = fmt.Errorf("unexpected text after encoded value: %q", r.text[r.pos:])
	}
	return v, r.line, err
}

func (r *smaliValueReader) skipSpace() bool {
	for {
		for r.pos < len(r.text) && (r.text[r.pos] == ' ' || r.text[r.pos] == '\t' || r.text[r.pos] == '\r') {
			r.pos++
		}
		if r.pos < len(r.text) {
			return true
		}
		if r.line+1 >= len(r.raw) {
			return false
		}
		r.line++
		r.text = stripSmaliCommentFull(r.raw[r.line])
		r.pos = 0
	}
}

func (r *smaliValueReader) value(depth int) (*SmaliValue, error) {
	if depth > 64 {
		return nil, fmt.Errorf("annotation value nesting exceeds 64")
	}
	if !r.skipSpace() {
		return nil, fmt.Errorf("missing encoded value")
	}
	if r.text[r.pos] == '{' {
		r.pos++
		v := &SmaliValue{Kind: "array"}
		for {
			if !r.skipSpace() {
				return nil, fmt.Errorf("unterminated array value")
			}
			if r.text[r.pos] == '}' {
				r.pos++
				return v, nil
			}
			e, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v.Elements = append(v.Elements, e)
			if !r.skipSpace() {
				return nil, fmt.Errorf("unterminated array value")
			}
			switch r.text[r.pos] {
			case ',':
				r.pos++
			case '}':
				r.pos++
				return v, nil
			default:
				return nil, fmt.Errorf("expected ',' or '}' in array value")
			}
		}
	}
	if strings.HasPrefix(r.text[r.pos:], ".subannotation ") {
		r.pos += len(".subannotation ")
		start := r.pos
		for r.pos < len(r.text) && r.text[r.pos] != ' ' && r.text[r.pos] != '\t' {
			r.pos++
		}
		typ := r.text[start:r.pos]
		if !strings.HasPrefix(typ, "L") || !strings.HasSuffix(typ, ";") {
			return nil, fmt.Errorf("bad subannotation type %q", typ)
		}
		a := &SmaliAnnotation{Type: typ, Visibility: "runtime"}
		for {
			if !r.skipSpace() {
				return nil, fmt.Errorf("unterminated subannotation %s", typ)
			}
			if strings.HasPrefix(r.text[r.pos:], ".end subannotation") {
				r.pos += len(".end subannotation")
				return &SmaliValue{Kind: "subannotation", Sub: a}, nil
			}
			eq := strings.IndexByte(r.text[r.pos:], '=')
			if eq < 0 {
				return nil, fmt.Errorf("bad subannotation element %q", r.text[r.pos:])
			}
			name := strings.TrimSpace(r.text[r.pos : r.pos+eq])
			if name == "" {
				return nil, fmt.Errorf("empty subannotation element name")
			}
			r.pos += eq + 1
			e, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			a.Elements = append(a.Elements, &SmaliElem{Name: name, Value: e})
		}
	}
	start := r.pos
	var quote byte
	escaped := false
	for r.pos < len(r.text) {
		c := r.text[r.pos]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		} else if c == ',' || c == '}' {
			break
		}
		r.pos++
	}
	return parseSmaliScalarValue(r.text[start:r.pos])
}
