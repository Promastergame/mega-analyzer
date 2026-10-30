package dataflow

import (
	"sort"
	"strconv"
	"strings"
)

func (s *sliceState) stopped() bool {
	if s.ctx != nil && s.ctx.Err() != nil {
		s.truncated = true
		return true
	}
	if s.maxSteps > 0 && s.steps >= s.maxSteps {
		s.truncated = true
		return true
	}
	return false
}

// Index once, in stable order. Previously the entire hierarchy was rebuilt
// for each virtual invoke, and map iteration changed truncated result order.
func (s *sliceState) buildAuditIndexes(signatures []string) {
	s.children = make(map[string][]string, len(s.classes))
	names := make([]string, 0, len(s.classes))
	for name := range s.classes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if s.stopped() {
			return
		}
		c := s.classes[name]
		if c.SuperClass != "" {
			s.children[c.SuperClass] = append(s.children[c.SuperClass], name)
		}
		for _, iface := range c.Interfaces {
			s.children[iface] = append(s.children[iface], name)
		}
	}
	s.fieldWrites = make(map[string][]fieldWrite)
	s.callers = make(map[string][]callReference)
	for _, signature := range signatures {
		if s.stopped() {
			return
		}
		method := s.methods[signature]
		for index, raw := range method.Body {
			if index&255 == 0 && s.stopped() {
				return
			}
			fields := smaliFields(cleanSmali(raw))
			if len(fields) >= 3 && (strings.HasPrefix(fields[0], "iput") || strings.HasPrefix(fields[0], "sput")) {
				field := fields[len(fields)-1]
				s.fieldWrites[field] = append(s.fieldWrites[field], fieldWrite{method: signature, line: index, register: fields[1]})
			}
			if call, ok := parseInvoke(raw); ok {
				for _, target := range s.resolveCallees(call) {
					s.callers[target] = append(s.callers[target], callReference{caller: signature, index: index, call: call})
				}
			}
		}
	}
}
func stripSmaliComment(raw string) string {
	quoted, escaped := false, false
	for i := 0; i < len(raw); i++ {
		if escaped {
			escaped = false
			continue
		}
		if quoted && raw[i] == '\\' {
			escaped = true
			continue
		}
		if raw[i] == '"' {
			quoted = !quoted
		}
		if raw[i] == '#' && !quoted {
			return strings.TrimSpace(raw[:i])
		}
	}
	return strings.TrimSpace(raw)
}
func definesRegister(op string) bool {
	// Read-only instructions must not be mistaken for overwrites.
	for _, prefix := range []string{"move", "const", "new-", "aget", "iget", "sget", "cmp", "add-", "sub-", "rsub-", "mul-", "div-", "rem-", "neg-", "not-", "and-", "or-", "xor-", "shl-", "shr-", "ushr-"} {
		if strings.HasPrefix(op, prefix) {
			return true
		}
	}
	return op == "array-length" || op == "instance-of" || op == "check-cast" || strings.Contains(op, "-to-")
}

// Incoming register words alias pN. Normalize only operands, not literals,
// class descriptors or method names. Keep one output line per physical line.
func normalizeParameterAliases(method methodData) []string {
	words := 0
	if !method.IsStatic {
		words++
	}
	for _, width := range parameterWidths(method.Params) {
		words += width
	}
	if words == 0 {
		return method.Body
	}
	total := -1
	for _, raw := range method.Body {
		f := strings.Fields(stripSmaliComment(raw))
		if len(f) < 2 {
			continue
		}
		if f[0] == ".registers" || f[0] == ".locals" {
			n, err := strconv.Atoi(f[1])
			if err != nil || n < 0 || n > 65535 {
				continue
			}
			total = n
			if f[0] == ".locals" {
				total += words
			}
			break
		}
	}
	if total < words || total > 65535 {
		return method.Body
	}
	base := total - words
	out := make([]string, len(method.Body))
	for i, line := range method.Body {
		out[i] = normalizeRegisterLine(line, base, total)
	}
	return out
}
func registerDelimiter(c byte) bool {
	return c == ' ' || c == '\t' || c == ',' || c == '{' || c == '}' || c == '\r'
}
func normalizeRegisterLine(line string, base, total int) string {
	var out strings.Builder
	out.Grow(len(line))
	quoted, escaped := false, false
	for i := 0; i < len(line); {
		c := line[i]
		if escaped {
			out.WriteByte(c)
			escaped = false
			i++
			continue
		}
		if quoted && c == '\\' {
			out.WriteByte(c)
			escaped = true
			i++
			continue
		}
		if c == '"' {
			quoted = !quoted
		}
		if c == '#' && !quoted {
			out.WriteString(line[i:])
			break
		}
		if !quoted && c == 'v' && (i == 0 || registerDelimiter(line[i-1])) {
			end := i + 1
			for end < len(line) && line[end] >= '0' && line[end] <= '9' {
				end++
			}
			if end > i+1 && (end == len(line) || registerDelimiter(line[end])) {
				n, err := strconv.Atoi(line[i+1 : end])
				if err == nil && n >= base && n < total {
					out.WriteByte('p')
					out.WriteString(strconv.Itoa(n - base))
					i = end
					continue
				}
			}
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

// Local fairness is independent of the global budget: resume at the next sink
// after a pathological slice, but retain an explicit incomplete-coverage flag.
func (s *sliceState) sliceStopped() bool {
	if s.stopped() {
		return true
	}
	if s.maxSinkSteps > 0 && s.sinkSteps >= s.maxSinkSteps {
		s.truncated = true
		s.sinkTruncated = true
		return true
	}
	return false
}
