package apkloader

// Native Smali text parser: .smali source → SmaliFile model.
//
// Accepts the dialect emitted by generateSmaliClassBytes plus the common
// baksmali/apktool superset (.locals, .end field, comments, :labels as
// branch targets). Directives the DEX writer cannot represent yet
// (.line, .local, .restart local, .prologue, .epilogue, .source already kept)
// are accepted and dropped with a recorded note so user edits to them never
// fail the build silently.

import (
	"fmt"
	"strconv"
	"strings"
)

// SmaliParseNote is a non-fatal observation (e.g. dropped debug directive).
type SmaliParseNote struct {
	Path string
	Line int
	Text string
}

// ParseSmaliFile parses one .smali source.
func ParseSmaliFile(path, text string) (*SmaliFile, []SmaliParseNote, error) {
	p := &smaliParser{path: path}
	return p.parse(text)
}

type smaliParser struct {
	path  string
	notes []SmaliParseNote
	file  *SmaliFile
	cur   *SmaliMethod
	inAnn *SmaliAnnotation
	annOf *[]*SmaliAnnotation
	line  int
	// Owner of the next top-level .annotation block.
	lastField *SmaliField
	// .param region tracking for parameter annotations.
	inParam  bool
	paramIdx int
	paramAnn []*SmaliAnnotation
}

func (p *smaliParser) note(line int, format string, args ...interface{}) {
	p.notes = append(p.notes, SmaliParseNote{Path: p.path, Line: line, Text: fmt.Sprintf(format, args...)})
}

func (p *smaliParser) parse(text string) (*SmaliFile, []SmaliParseNote, error) {
	p.file = &SmaliFile{Path: p.path}
	rawLines := strings.Split(text, "\n")
	// Pending label definitions attach to the next code line/payload.
	var pendingLabels []string
	i := 0
	for ; i < len(rawLines); i++ {
		p.line = i + 1
		line := stripSmaliCommentFull(rawLines[i])
		if line == "" {
			continue
		}
		if p.inAnn != nil {
			if line == ".end annotation" {
				*p.annOf = append(*p.annOf, p.inAnn)
				p.inAnn = nil
				p.annOf = nil
				continue
			}
			// name = value
			eq := strings.Index(line, "=")
			if eq < 0 {
				return nil, p.notes, fmt.Errorf("%s:%d: bad annotation element %q", p.path, p.line, line)
			}
			name := strings.TrimSpace(line[:eq])
			v, next, err := parseSmaliValueLines(strings.TrimSpace(line[eq+1:]), rawLines, i)
			if err != nil {
				return nil, p.notes, fmt.Errorf("%s:%d: %v", p.path, p.line, err)
			}
			i = next
			p.inAnn.Elements = append(p.inAnn.Elements, &SmaliElem{Name: name, Value: v})
			continue
		}
		if p.cur == nil {
			if err := p.parseTopLine(line, &pendingLabels); err != nil {
				return nil, p.notes, err
			}
			continue
		}
		// Inside a method.
		if line == ".end method" {
			if err := p.finishParam(); err != nil {
				return nil, p.notes, err
			}
			for _, label := range pendingLabels {
				p.cur.Lines = append(p.cur.Lines, &SmaliLine{Kind: LineLabel, Label: label})
			}
			p.cur = nil
			pendingLabels = nil
			continue
		}
		if err := p.parseBodyLine(line, &pendingLabels, rawLines, &i); err != nil {
			return nil, p.notes, err
		}
	}
	if p.inAnn != nil {
		return nil, p.notes, fmt.Errorf("%s: unterminated .annotation %s", p.path, p.inAnn.Type)
	}
	if p.cur != nil {
		return nil, p.notes, fmt.Errorf("%s: unterminated .method %s", p.path, p.cur.Name)
	}
	if p.file.Class == "" {
		return nil, p.notes, fmt.Errorf("%s: missing .class directive", p.path)
	}
	return p.file, p.notes, nil
}

func (p *smaliParser) parseTopLine(line string, pending *[]string) error {
	if !strings.HasPrefix(line, ".annotation ") && line != ".end field" {
		p.lastField = nil
	}
	switch {
	case strings.HasPrefix(line, ".class "):
		if p.file.Class != "" {
			return fmt.Errorf("%s:%d: duplicate .class directive", p.path, p.line)
		}
		rest := strings.TrimSpace(line[len(".class "):])
		words := strings.Fields(rest)
		if len(words) < 1 {
			return fmt.Errorf("%s:%d: bad .class %q", p.path, p.line, line)
		}
		cls := words[len(words)-1]
		acc, err := parseAccessFlags(words[:len(words)-1], false)
		if err != nil {
			return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
		}
		p.file.Class = cls
		p.file.Access = acc
		return nil
	case strings.HasPrefix(line, ".super "):
		p.file.Super = strings.TrimSpace(line[len(".super "):])
		return nil
	case strings.HasPrefix(line, ".source "):
		s, err := unquoteSmaliString(strings.TrimSpace(line[len(".source "):]))
		if err != nil {
			return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
		}
		p.file.Source = s
		return nil
	case strings.HasPrefix(line, ".implements "):
		p.file.Interfaces = append(p.file.Interfaces, strings.TrimSpace(line[len(".implements "):]))
		return nil
	case strings.HasPrefix(line, ".field "):
		return p.parseField(strings.TrimSpace(line[len(".field "):]))
	case strings.HasPrefix(line, ".method "):
		return p.parseMethodHead(strings.TrimSpace(line[len(".method "):]))
	case strings.HasPrefix(line, ".annotation "):
		a, err := parseAnnotationHead(strings.TrimSpace(line[len(".annotation "):]))
		if err != nil {
			return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
		}
		p.inAnn = a
		// Annotations directly after a .field belong to that field.
		if p.lastField != nil {
			p.annOf = &p.lastField.Annotations
		} else {
			p.annOf = &p.file.Annotations
		}
		return nil
	case strings.HasPrefix(line, ".end annotation"):
		return fmt.Errorf("%s:%d: .end annotation without .annotation", p.path, p.line)
	case line == ".end field":
		p.lastField = nil
		return nil
	case strings.HasPrefix(line, "#"):
		return nil
	}
	return fmt.Errorf("%s:%d: unexpected line outside method: %q", p.path, p.line, line)
}

func parseAnnotationHead(rest string) (*SmaliAnnotation, error) {
	words := strings.Fields(rest)
	if len(words) != 2 {
		return nil, fmt.Errorf("bad .annotation %q", rest)
	}
	switch words[0] {
	case "build", "runtime", "system":
	default:
		return nil, fmt.Errorf("bad annotation visibility %q", words[0])
	}
	return &SmaliAnnotation{Visibility: words[0], Type: words[1]}, nil
}

func (p *smaliParser) parseField(rest string) error {
	// name:type [= value], flags first.
	eq := -1
	// Find '=' outside quotes.
	inStr, esc := false, false
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			continue
		}
		if c == '=' {
			eq = i
			break
		}
	}
	head := rest
	var initText string
	hasInit := false
	if eq >= 0 {
		head = strings.TrimSpace(rest[:eq])
		initText = strings.TrimSpace(rest[eq+1:])
		hasInit = true
	}
	colon := strings.LastIndex(head, ":")
	if colon < 0 {
		return fmt.Errorf("%s:%d: bad .field %q", p.path, p.line, rest)
	}
	nameFlags := strings.TrimSpace(head[:colon])
	typ := strings.TrimSpace(head[colon+1:])
	words := strings.Fields(nameFlags)
	if len(words) < 1 {
		return fmt.Errorf("%s:%d: bad .field %q", p.path, p.line, rest)
	}
	name := words[len(words)-1]
	acc, err := parseAccessFlags(words[:len(words)-1], true)
	if err != nil {
		return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
	}
	f := &SmaliField{Name: name, Type: typ, Access: acc}
	if hasInit {
		v, err := parseSmaliValue(initText)
		if err != nil {
			// Trypromotion: our emitter writes ints plain; be lenient.
			return fmt.Errorf("%s:%d: bad field initializer: %v", p.path, p.line, err)
		}
		f.Initializer = v
	}
	// Inline annotations on following lines are handled by body parser? No:
	// fields are top-level; annotations follow as .annotation blocks. We peek
	// nothing here; parseTopLine routes .annotation to p.inAnn with annOf set
	// below via a small state: remember last field.
	p.file.Fields = append(p.file.Fields, f)
	p.lastField = f
	_ = hasInit
	return nil
}

// lastField tracks the owner of a following .annotation block.
func (p *smaliParser) parseMethodHead(rest string) error {
	words := strings.Fields(rest)
	if len(words) < 1 {
		return fmt.Errorf("%s:%d: bad .method %q", p.path, p.line, rest)
	}
	sig := words[len(words)-1]
	acc, err := parseAccessFlags(words[:len(words)-1], false)
	if err != nil {
		return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
	}
	lp := strings.Index(sig, "(")
	rp := strings.LastIndex(sig, ")")
	if lp < 0 || rp < 0 || rp < lp {
		return fmt.Errorf("%s:%d: bad method signature %q", p.path, p.line, sig)
	}
	name := sig[:lp]
	params, err := splitParams(sig[lp+1 : rp])
	if err != nil {
		return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
	}
	ret := sig[rp+1:]
	m := &SmaliMethod{Name: name, Params: params, Return: ret, Access: acc, Registers: -1, ParamAnnots: map[int][]*SmaliAnnotation{}}
	p.file.Methods = append(p.file.Methods, m)
	p.cur = m
	p.lastField = nil
	p.inParam = false
	p.paramAnn = nil
	return nil
}

func (p *smaliParser) parseBodyLine(line string, pending *[]string, raw []string, idx *int) error {
	m := p.cur
	// Annotations inside methods attach to the method, or to the current
	// .param region when inside one.
	if strings.HasPrefix(line, ".annotation ") {
		a, err := parseAnnotationHead(strings.TrimSpace(line[len(".annotation "):]))
		if err != nil {
			return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
		}
		p.inAnn = a
		if p.inParam {
			p.annOf = &p.paramAnn
		} else {
			p.annOf = &m.Annotations
		}
		return nil
	}
	// .param pN — opens a region closed by .end param.
	if strings.HasPrefix(line, ".param ") {
		if err := p.finishParam(); err != nil {
			return err
		}
		rest := strings.TrimSpace(line[len(".param "):])
		reg := strings.TrimSpace(strings.SplitN(rest, ",", 2)[0])
		ordinal, err := parameterOrdinal(m, reg)
		if err != nil {
			return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
		}
		p.inParam = true
		p.paramAnn = nil
		p.paramIdx = ordinal
		return nil
	}
	if line == ".end param" {
		if !p.inParam {
			return fmt.Errorf("%s:%d: .end param without .param", p.path, p.line)
		}
		return p.finishParam()
	}
	if err := p.finishParam(); err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(line, ".registers "):
		n, err := strconv.Atoi(strings.TrimSpace(line[len(".registers "):]))
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("%s:%d: bad .registers %q", p.path, p.line, line)
		}
		m.Registers = n
		return nil
	case strings.HasPrefix(line, ".locals "):
		n, err := strconv.Atoi(strings.TrimSpace(line[len(".locals "):]))
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("%s:%d: bad .locals %q", p.path, p.line, line)
		}
		m.Registers = n // resolved to registers after params known
		m.UsesLocals = true
		return nil
	case strings.HasPrefix(line, ".catch ") || strings.HasPrefix(line, ".catchall "):
		c, err := parseCatchLine(line)
		if err != nil {
			return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
		}
		// Pending labels (e.g. :try_end on the previous line) belong to the
		// next code line, not to the directive: keep them.
		m.Lines = append(m.Lines, &SmaliLine{Kind: LineCatch, Catch: c, Raw: line})
		return nil
	case strings.HasPrefix(line, ".packed-switch ") || line == ".packed-switch" ||
		strings.HasPrefix(line, ".sparse-switch") || strings.HasPrefix(line, ".array-data"):
		pl, next, err := parsePayloadBlock(line, raw, idx)
		if err != nil {
			return fmt.Errorf("%s:%d: %v", p.path, p.line, err)
		}
		pl.Labels = append([]string(nil), *pending...)
		*pending = nil
		*idx = next
		p.line = next + 1
		m.Lines = append(m.Lines, &SmaliLine{Kind: LinePayload, Payload: pl, Raw: line})
		return nil
	case strings.HasPrefix(line, ".end ") || (strings.HasPrefix(line, ".") && !strings.HasPrefix(line, ".param")):
		// Dropped debug directives (.line, .local, .prologue, ...) — note it.
		if strings.HasPrefix(line, ".line ") || strings.HasPrefix(line, ".local ") ||
			strings.HasPrefix(line, ".end local ") ||
			strings.HasPrefix(line, ".restart ") || line == ".prologue" || line == ".epilogue" ||
			strings.HasPrefix(line, ".source ") || strings.HasPrefix(line, ".limit ") {
			p.note(p.line, "dropped debug directive %q", line)
			return nil
		}
		return fmt.Errorf("%s:%d: unexpected directive %q", p.path, p.line, line)
	case strings.HasPrefix(line, ":"):
		name := strings.Fields(line)[0]
		*pending = append(*pending, name)
		return nil
	}
	// Instruction: mnemonic + operands.
	// Flush pending labels as label lines.
	for _, l := range *pending {
		m.Lines = append(m.Lines, &SmaliLine{Kind: LineLabel, Label: l})
	}
	*pending = nil
	sp := strings.IndexAny(line, " \t")
	mn := line
	ops := ""
	if sp >= 0 {
		mn = line[:sp]
		ops = strings.TrimSpace(line[sp+1:])
	}
	if !isMnemonic(mn) {
		return fmt.Errorf("%s:%d: unknown instruction %q", p.path, p.line, mn)
	}
	m.Lines = append(m.Lines, &SmaliLine{Kind: LineInsn, Mnemonic: mn, Operands: ops, Raw: line})
	return nil
}

func (p *smaliParser) finishParam() error {
	if !p.inParam {
		return nil
	}
	if len(p.paramAnn) > 0 {
		if p.paramIdx < 0 {
			return fmt.Errorf("%s:%d: receiver p0 cannot have parameter annotations", p.path, p.line)
		}
		p.cur.ParamAnnots[p.paramIdx] = append(p.cur.ParamAnnots[p.paramIdx], p.paramAnn...)
	}
	p.inParam = false
	p.paramAnn = nil
	return nil
}

// DEX annotations are indexed by declared argument, whereas Smali pN names
// register slots (including this and the second half of long/double values).
func parameterOrdinal(m *SmaliMethod, reg string) (int, error) {
	if len(reg) < 2 || (reg[0] != 'p' && reg[0] != 'v') {
		return 0, fmt.Errorf("bad parameter register %q", reg)
	}
	n, err := strconv.Atoi(reg[1:])
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad parameter register %q", reg)
	}
	if reg[0] == 'v' {
		registers, slots, err := smaliRegisterWindow(m)
		if err != nil {
			return 0, err
		}
		n -= registers - slots
	}
	slot := 0
	if m.Access&0x0008 == 0 {
		if n == 0 {
			return -1, nil
		}
		slot++
	}
	for i, typ := range m.Params {
		if slot == n {
			return i, nil
		}
		slot++
		if typ == "J" || typ == "D" {
			slot++
		}
	}
	return 0, fmt.Errorf("%s is not the first register of a declared parameter", reg)
}

func parseCatchLine(line string) (*SmaliCatch, error) {
	if strings.HasPrefix(line, ".catchall ") {
		rest := strings.TrimSpace(line[len(".catchall "):])
		// {:a .. :b} :handler
		from, to, handler, err := parseTryRange(rest)
		if err != nil {
			return nil, err
		}
		return &SmaliCatch{TryFrom: from, TryTo: to, Handler: handler}, nil
	}
	rest := strings.TrimSpace(line[len(".catch "):])
	// <type> {:a .. :b} :handler
	sp := strings.IndexAny(rest, " \t")
	if sp < 0 {
		return nil, fmt.Errorf("bad .catch %q", line)
	}
	typ := rest[:sp]
	from, to, handler, err := parseTryRange(strings.TrimSpace(rest[sp+1:]))
	if err != nil {
		return nil, err
	}
	return &SmaliCatch{Type: typ, TryFrom: from, TryTo: to, Handler: handler}, nil
}

func parseTryRange(s string) (from, to, handler string, err error) {
	// {:from .. :to} :handler
	if !strings.HasPrefix(s, "{") {
		return "", "", "", fmt.Errorf("bad try range %q", s)
	}
	close := strings.Index(s, "}")
	if close < 0 {
		return "", "", "", fmt.Errorf("bad try range %q", s)
	}
	inner := s[1:close]
	parts := strings.Split(inner, "..")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("bad try range %q", s)
	}
	handler = strings.TrimSpace(s[close+1:])
	if !strings.HasPrefix(handler, ":") {
		return "", "", "", fmt.Errorf("bad catch handler %q", s)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.Fields(handler)[0], nil
}

func parsePayloadBlock(first string, raw []string, idx *int) (*SmaliPayload, int, error) {
	var kind, arg string
	switch {
	case strings.HasPrefix(first, ".packed-switch"):
		kind = "packed-switch"
		arg = strings.TrimSpace(strings.TrimPrefix(first, ".packed-switch"))
	case strings.HasPrefix(first, ".sparse-switch"):
		kind = "sparse-switch"
	case strings.HasPrefix(first, ".array-data"):
		kind = "array-data"
		arg = strings.TrimSpace(strings.TrimPrefix(first, ".array-data"))
	}
	pl := &SmaliPayload{Kind: kind, Arg: arg}
	end := ".end " + kind
	i := *idx
	for i++; i < len(raw); i++ {
		l := stripSmaliCommentFull(raw[i])
		if l == "" {
			continue
		}
		if l == end {
			return pl, i, nil
		}
		if (strings.HasPrefix(l, ":") && kind != "packed-switch") || strings.HasPrefix(l, ".") {
			return nil, i, fmt.Errorf("bad payload line %q", l)
		}
		pl.Items = append(pl.Items, l)
	}
	return nil, i, fmt.Errorf("unterminated %s block", kind)
}

// isMnemonic reports whether word is a known Dalvik mnemonic.
func isMnemonic(w string) bool {
	_, ok := smaliMnemonics[w]
	return ok
}
