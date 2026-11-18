package smalirole

import (
	"regexp"
	"strings"
)

// Insn is one Dalvik instruction as written by baksmali/apktool.
type Insn struct {
	Line int      // 1-based line inside the method text
	Op   string   // opcode, e.g. "and-int/2addr"
	Regs []string // register operands in order ({v0 .. v3} ranges expanded)
	Raw  string   // instruction without comment
}

// Method is a parsed .method … .end method block.
type Method struct {
	Class   string // Lcom/foo/Bar;
	Name    string
	Params  []string // JVM descriptors without implicit this
	Ret     string
	Static  bool
	Text    string
	Insns   []Insn
	Labels  map[string]int // label -> index in Insns
	Payload map[string]bool
}

var regRE = regexp.MustCompile(`\b[vp]\d+\b`)
var rangeRE = regexp.MustCompile(`\{\s*([vp])(\d+)\s*\.\.\s*[vp](\d+)\s*\}`)

func stripComment(s string) string {
	q, esc := false, false
	for i, c := range s {
		switch {
		case esc:
			esc = false
		case c == '\\' && q:
			esc = true
		case c == '"':
			q = !q
		case c == '#' && !q:
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

func stripStrings(s string) string {
	var b strings.Builder
	q, esc := false, false
	for _, c := range s {
		switch {
		case esc:
			esc = false
			continue
		case c == '\\' && q:
			esc = true
			continue
		case c == '"':
			q = !q
			b.WriteRune('"')
			continue
		}
		if !q {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// SplitDescriptors splits "ILjava/lang/String;[JZ" into ["I","Ljava/lang/String;","[J","Z"].
func SplitDescriptors(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] == '[' {
			j++
		}
		if j < len(s) && s[j] == 'L' {
			k := strings.IndexByte(s[j:], ';')
			if k < 0 {
				return out
			}
			j += k
		}
		out = append(out, s[i:j+1])
		i = j + 1
	}
	return out
}

func expandRange(l string) string {
	return rangeRE.ReplaceAllStringFunc(l, func(m string) string {
		p := rangeRE.FindStringSubmatch(m)
		a, b := atoi(p[2]), atoi(p[3])
		var rs []string
		for i := a; i <= b && i-a < 64; i++ {
			rs = append(rs, p[1]+itoa(i))
		}
		return "{" + strings.Join(rs, ", ") + "}"
	})
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// ParseMethod parses one method; lines are numbered from the start of text.
func ParseMethod(class, text string) *Method {
	m := &Method{Class: class, Text: text, Labels: map[string]int{}, Payload: map[string]bool{}}
	inPayload := false
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		l := stripComment(raw)
		switch {
		case l == "":
		case strings.HasPrefix(l, ".method"):
			m.Static = strings.Contains(l, " static ")
			sig := l[strings.LastIndex(l, " ")+1:]
			if p := strings.IndexByte(sig, '('); p > 0 {
				m.Name = sig[:p]
				q := strings.IndexByte(sig, ')')
				m.Params = SplitDescriptors(sig[p+1 : q])
				m.Ret = sig[q+1:]
			}
		case strings.HasPrefix(l, ".packed-switch"), strings.HasPrefix(l, ".sparse-switch"), strings.HasPrefix(l, ".array-data"):
			inPayload = true
		case strings.HasPrefix(l, ".end packed-switch"), strings.HasPrefix(l, ".end sparse-switch"), strings.HasPrefix(l, ".end array-data"):
			inPayload = false
		case inPayload:
		case strings.HasPrefix(l, ":"):
			m.Labels[strings.Fields(l)[0]] = len(m.Insns)
		case strings.HasPrefix(l, "."):
		default:
			f := strings.Fields(l)
			body := expandRange(stripStrings(strings.TrimPrefix(l, f[0])))
			if k := strings.Index(body, "->"); k >= 0 { // do not read registers out of type names
				body = body[:k]
			}
			if strings.HasPrefix(f[0], "const-string") || strings.HasPrefix(f[0], "const-class") {
				body = strings.SplitN(body, ",", 2)[0]
			}
			m.Insns = append(m.Insns, Insn{Line: i + 1, Op: f[0], Regs: regRE.FindAllString(body, -1), Raw: l})
		}
	}
	return m
}

// ParseFile splits a .smali class file into methods.
func ParseFile(text string) []*Method {
	class := ""
	var out []*Method
	lines := strings.Split(text, "\n")
	start := -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, ".class") {
			class = t[strings.LastIndex(t, " ")+1:]
		} else if strings.HasPrefix(t, ".method") {
			start = i
		} else if strings.HasPrefix(t, ".end method") && start >= 0 {
			out = append(out, ParseMethod(class, strings.Join(lines[start:i+1], "\n")))
			start = -1
		}
	}
	return out
}

// ParamRegister maps a declared parameter index to its p-register name (wide types take two).
func (m *Method) ParamRegister(idx int) string {
	p := 0
	if !m.Static {
		p = 1
	}
	for i := 0; i < idx && i < len(m.Params); i++ {
		p++
		if m.Params[i] == "J" || m.Params[i] == "D" {
			p++
		}
	}
	return "p" + itoa(p)
}
