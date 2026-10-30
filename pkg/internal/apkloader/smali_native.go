package apkloader

// Native Smali model and text parser.
//
// This is the front end of the built-in Smali→DEX assembler. It parses the
// dialect produced by generateSmaliClassBytes (and the common baksmali/
// apktool superset: :labels, .locals, .end field, comments) into a
// structured SmaliFile ready for assembly. No external tools are involved.

import (
	"fmt"
	"strconv"
	"strings"
)

// ── Model ────────────────────────────────────────────────────────────────────

// SmaliFile is one parsed .smali source: exactly one top-level class.
type SmaliFile struct {
	Path       string
	Class      string // e.g. Lcom/a/B;
	Access     uint32
	Super      string
	Source     string
	Interfaces []string
	Fields     []*SmaliField
	Methods    []*SmaliMethod
	// Annotations on the class itself.
	Annotations []*SmaliAnnotation
}

// SmaliField is one .field declaration.
type SmaliField struct {
	Name        string
	Type        string
	Access      uint32
	Initializer *SmaliValue // nil when absent
	Annotations []*SmaliAnnotation
}

// SmaliMethod is one .method block.
type SmaliMethod struct {
	Name        string
	Params      []string
	Return      string
	Access      uint32
	Registers   int // -1 when neither .registers nor .locals present
	UsesLocals  bool
	Lines       []*SmaliLine // code lines in order (labels, insns, payloads, catch directives)
	Annotations []*SmaliAnnotation
	ParamAnnots map[int][]*SmaliAnnotation
}

// SmaliLine is a single parsed body line.
type SmaliLine struct {
	Kind SmaliLineKind
	// Label definition (LineLabel).
	Label string
	// Instruction (LineInsn): mnemonic + raw operand text.
	Mnemonic string
	Operands string
	// Payload block (SmaliPayload): one of packed-switch/sparse-switch/array-data.
	Payload *SmaliPayload
	// Catch directive (SmaliCatch).
	Catch *SmaliCatch
	// .param line (informational; skipped by the assembler).
	Raw string
	// parsed caches parseInsnOperands for LineInsn lines.
	parsed *asmInsn
}

// SmaliLineKind classifies a method body line.
type SmaliLineKind int

const (
	LineRaw SmaliLineKind = iota
	LineLabel
	LineInsn
	LinePayload
	LineCatch
)

// SmaliPayload is a switch/array data block.
type SmaliPayload struct {
	Kind   string // "packed-switch", "sparse-switch", "array-data"
	Arg    string // first-key (packed) or elem width (array-data); "" for sparse
	Items  []string
	Labels []string // label definition(s) attached to the block start
}

// SmaliCatch is a .catch/.catchall directive.
type SmaliCatch struct {
	Type    string // "" for catchall
	TryFrom string
	TryTo   string
	Handler string
}

// SmaliAnnotation is one .annotation block.
type SmaliAnnotation struct {
	Visibility string // build|runtime|system
	Type       string
	Elements   []*SmaliElem
}

// SmaliElem is one name = value pair.
type SmaliElem struct {
	Name  string
	Value *SmaliValue
}

// SmaliValue is a parsed encoded value.
type SmaliValue struct {
	Kind     string // int,long,float,double,boolean,string,type,field,method,null,array,subannotation,enum,char,byte,short
	Int      int64
	Float    float64
	Str      string
	Elements []*SmaliValue
	Sub      *SmaliAnnotation
}

// ── Access flags ─────────────────────────────────────────────────────────────

var smaliFlagByName = map[string]uint32{
	"public": 0x0001, "private": 0x0002, "protected": 0x0004,
	"static": 0x0008, "final": 0x0010, "synchronized": 0x0020,
	"bridge": 0x0040, "varargs": 0x0080, "native": 0x0100,
	"interface": 0x0200, "abstract": 0x0400, "strictfp": 0x0800,
	"synthetic": 0x1000, "annotation": 0x2000, "enum": 0x4000,
	"constructor": 0x10000, "declared-synchronized": 0x20000,
	"volatile": 0x0040, "transient": 0x0080,
}

// parseAccessFlags folds smali flag words. isField selects the field meaning
// of 0x40/0x80 (volatile/transient) over the method meaning (bridge/varargs).
func parseAccessFlags(words []string, isField bool) (uint32, error) {
	var out uint32
	for _, w := range words {
		f, ok := smaliFlagByName[w]
		if !ok {
			return 0, fmt.Errorf("unknown access flag %q", w)
		}
		_ = isField
		out |= f
	}
	return out, nil
}

// ── Comment handling ─────────────────────────────────────────────────────────

func stripSmaliCommentFull(line string) string {
	var b strings.Builder
	var quote byte
	esc := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			b.WriteByte(c)
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == '#' {
			break
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

// splitTopLevel splits s on sep except inside quotes, braces and parens.
func splitTopLevel(s string, sep byte) []string {
	var parts []string
	var b strings.Builder
	depthBrace, depthParen := 0, 0
	inStr, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			b.WriteByte(c)
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
			b.WriteByte(c)
		case '{':
			depthBrace++
			b.WriteByte(c)
		case '}':
			if depthBrace > 0 {
				depthBrace--
			}
			b.WriteByte(c)
		case '(':
			depthParen++
			b.WriteByte(c)
		case ')':
			if depthParen > 0 {
				depthParen--
			}
			b.WriteByte(c)
		default:
			if c == sep && depthBrace == 0 && depthParen == 0 {
				parts = append(parts, strings.TrimSpace(b.String()))
				b.Reset()
			} else {
				b.WriteByte(c)
			}
		}
	}
	parts = append(parts, strings.TrimSpace(b.String()))
	return parts
}

// ── Literals ─────────────────────────────────────────────────────────────────

// parseSmaliInt parses decimal/hex smali integers with optional L/F/D suffix.
func parseSmaliInt(s string) (int64, error) {
	t := strings.TrimSpace(s)
	t = strings.TrimRight(t, "LlTtSs")
	neg := false
	if strings.HasPrefix(t, "+") {
		t = t[1:]
	} else if strings.HasPrefix(t, "-") {
		neg = true
		t = t[1:]
	}
	var v uint64
	var err error
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		v, err = strconv.ParseUint(t[2:], 16, 64)
	} else {
		var sv int64
		sv, err = strconv.ParseInt(t, 10, 64)
		if err == nil {
			if neg {
				sv = -sv
			}
			return sv, nil
		}
		v, err = strconv.ParseUint(t, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("bad integer %q", s)
		}
		if neg {
			return -int64(v), nil
		}
		return int64(v), nil
	}
	if err != nil {
		return 0, fmt.Errorf("bad integer %q", s)
	}
	if neg {
		return -int64(v), nil
	}
	return int64(v), nil
}

// unquoteSmaliString decodes a quoted smali string literal.
func unquoteSmaliString(s string) (string, error) {
	t := strings.TrimSpace(s)
	if len(t) < 2 || t[0] != '"' || t[len(t)-1] != '"' {
		return "", fmt.Errorf("bad string literal %q", s)
	}
	inner := t[1 : len(t)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(inner) {
			return "", fmt.Errorf("trailing backslash in %q", s)
		}
		switch inner[i] {
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
		case '"':
			b.WriteByte('"')
		case '\'':
			b.WriteByte('\'')
		case '\\':
			b.WriteByte('\\')
		case 'u':
			if i+4 >= len(inner) {
				return "", fmt.Errorf("bad \\u escape in %q", s)
			}
			n, err := strconv.ParseUint(inner[i+1:i+5], 16, 32)
			if err != nil {
				return "", fmt.Errorf("bad \\u escape in %q", s)
			}
			b.WriteRune(rune(n))
			i += 4
		default:
			b.WriteByte(inner[i])
		}
	}
	return b.String(), nil
}

// parseSmaliScalarValue parses a non-container encoded value.
func parseSmaliScalarValue(s string) (*SmaliValue, error) {
	t := strings.TrimSpace(s)
	switch {
	case t == "null":
		return &SmaliValue{Kind: "null"}, nil
	case t == "true":
		return &SmaliValue{Kind: "boolean", Int: 1}, nil
	case t == "false":
		return &SmaliValue{Kind: "boolean", Int: 0}, nil
	case strings.HasPrefix(t, "\""):
		v, err := unquoteSmaliString(t)
		if err != nil {
			return nil, err
		}
		return &SmaliValue{Kind: "string", Str: v}, nil
	case strings.HasPrefix(t, ".enum "):
		return &SmaliValue{Kind: "enum", Str: strings.TrimSpace(t[len(".enum "):])}, nil
	case len(t) >= 3 && t[0] == '\'' && t[len(t)-1] == '\'':
		r, _, tail, err := strconv.UnquoteChar(t[1:len(t)-1], '\'')
		if err != nil || tail != "" || r > 65535 {
			return nil, fmt.Errorf("bad char literal %q", s)
		}
		return &SmaliValue{Kind: "char", Int: int64(r)}, nil
	}
	// float/double with suffix
	if strings.HasSuffix(t, "f") || strings.HasSuffix(t, "F") {
		f, err := strconv.ParseFloat(t[:len(t)-1], 32)
		if err == nil {
			return &SmaliValue{Kind: "float", Float: f}, nil
		}
	}
	if strings.ContainsAny(t, ".eE") || strings.HasSuffix(t, "d") || strings.HasSuffix(t, "D") || t == "NaN" || strings.HasSuffix(t, "Infinity") || strings.HasSuffix(t, "Inf") {
		f, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSuffix(t, "d"), "D"), 64)
		if err == nil {
			return &SmaliValue{Kind: "double", Float: f}, nil
		}
	}
	// type / field / method references
	if strings.Contains(t, ";->") {
		if strings.Contains(t, "(") {
			return &SmaliValue{Kind: "method", Str: t}, nil
		}
		return &SmaliValue{Kind: "field", Str: t}, nil
	}
	if (strings.HasPrefix(t, "L") && strings.HasSuffix(t, ";")) || len(t) == 1 && strings.ContainsAny(t, "ZBSCIJFDV") || strings.HasPrefix(t, "[") {
		return &SmaliValue{Kind: "type", Str: t}, nil
	}
	// integer (possibly with L suffix already handled by parseSmaliInt)
	i, err := parseSmaliInt(t)
	if err == nil {
		if strings.HasSuffix(t, "t") || strings.HasSuffix(t, "T") {
			if i < -128 || i > 255 {
				return nil, fmt.Errorf("byte value out of range: %q", s)
			}
			return &SmaliValue{Kind: "byte", Int: int64(int8(i))}, nil
		}
		if strings.HasSuffix(t, "s") || strings.HasSuffix(t, "S") {
			if i < -32768 || i > 65535 {
				return nil, fmt.Errorf("short value out of range: %q", s)
			}
			return &SmaliValue{Kind: "short", Int: int64(int16(i))}, nil
		}
		if strings.HasSuffix(t, "L") || strings.HasSuffix(t, "l") {
			return &SmaliValue{Kind: "long", Int: i}, nil
		}
		return &SmaliValue{Kind: "int", Int: i}, nil
	}
	return nil, fmt.Errorf("cannot parse value %q", s)
}

// ── Descriptors ──────────────────────────────────────────────────────────────

// splitMethodRef splits Lcls;->name(params)ret into class, name, params, ret.
func splitMethodRef(ref string) (cls, name string, params []string, ret string, err error) {
	arrow := strings.Index(ref, "->")
	if arrow < 0 {
		return "", "", nil, "", fmt.Errorf("bad method ref %q", ref)
	}
	cls = ref[:arrow]
	rest := ref[arrow+2:]
	lp := strings.Index(rest, "(")
	rp := strings.LastIndex(rest, ")")
	if lp < 0 || rp < 0 || rp < lp {
		return "", "", nil, "", fmt.Errorf("bad method ref %q", ref)
	}
	name = rest[:lp]
	var perr error
	params, perr = splitParams(rest[lp+1 : rp])
	if perr != nil {
		return "", "", nil, "", fmt.Errorf("bad method ref %q: %v", ref, perr)
	}
	ret = rest[rp+1:]
	if ret == "" {
		return "", "", nil, "", fmt.Errorf("bad method ref %q", ref)
	}
	return cls, name, params, ret, nil
}

// splitParams splits a packed type list like "ILjava/lang/String;[B".
func splitParams(s string) ([]string, error) {
	var out []string
	i := 0
	for i < len(s) {
		switch s[i] {
		case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
			out = append(out, s[i:i+1])
			i++
		case 'V':
			return nil, fmt.Errorf("void in parameter list")
		case 'L':
			j := strings.IndexByte(s[i:], ';')
			if j < 0 {
				return nil, fmt.Errorf("unterminated object type in %q", s)
			}
			out = append(out, s[i:i+j+1])
			i += j + 1
		case '[':
			j := i
			for j < len(s) && s[j] == '[' {
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("bad array type in %q", s)
			}
			if s[j] == 'L' {
				k := strings.IndexByte(s[j:], ';')
				if k < 0 {
					return nil, fmt.Errorf("unterminated object type in %q", s)
				}
				out = append(out, s[i:j+k+1])
				i = j + k + 1
			} else if strings.ContainsRune("ZBSCIJFD", rune(s[j])) {
				out = append(out, s[i:j+1])
				i = j + 1
			} else {
				return nil, fmt.Errorf("bad array type in %q", s)
			}
		default:
			return nil, fmt.Errorf("bad type char %q in %q", s[i], s)
		}
	}
	return out, nil
}

// splitFieldRef splits Lcls;->name:Type.
func splitFieldRef(ref string) (cls, name, typ string, err error) {
	arrow := strings.Index(ref, "->")
	colon := strings.LastIndex(ref, ":")
	if arrow < 0 || colon < 0 || colon < arrow {
		return "", "", "", fmt.Errorf("bad field ref %q", ref)
	}
	return ref[:arrow], ref[arrow+2 : colon], ref[colon+1:], nil
}

// shortyFor builds a shorty string from return + params.
func shortyFor(ret string, params []string) string {
	var b strings.Builder
	b.WriteString(shortyChar(ret))
	for _, p := range params {
		b.WriteString(shortyChar(p))
	}
	return b.String()
}

func shortyChar(t string) string {
	if t == "" {
		return "V"
	}
	switch t[0] {
	case '[', 'L':
		return "L"
	default:
		return t[:1]
	}
}
