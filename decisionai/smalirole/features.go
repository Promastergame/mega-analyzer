package smalirole

import (
	"regexp"
	"strings"
)

var ConstRE = regexp.MustCompile(`^(const(?:/4|/16|/high16)?|const-wide(?:/16|/32|/high16)?)\s+([vp]\d+)\s*,\s*(-?(?:0x[0-9a-fA-F]+|\d+))[lL]?$`)

// parseWide parses a 64-bit literal (const-wide*).
func parseWide(s string) (int64, uint64, error) {
	neg := strings.HasPrefix(s, "-")
	t := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(s, "-"), "L"), "l")
	base := 10
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		base, t = 16, t[2:]
	}
	var u uint64
	for _, c := range strings.ToLower(t) {
		d := strings.IndexRune("0123456789abcdef", c)
		if d < 0 || d >= base {
			return 0, 0, errBadLiteral
		}
		if u > (^uint64(0))/uint64(base) {
			return 0, 0, errBadLiteral
		}
		u = u*uint64(base) + uint64(d)
	}
	if neg {
		return -int64(u), uint64(-int64(u)), nil
	}
	return int64(u), u, nil
}

func parseLiteral(s string) (int64, uint64, error) {
	neg := strings.HasPrefix(s, "-")
	t := strings.TrimPrefix(s, "-")
	base := 10
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		base, t = 16, t[2:]
	}
	var u uint64
	for _, c := range strings.ToLower(t) {
		d := strings.IndexRune("0123456789abcdef", c)
		if d < 0 || d >= base {
			return 0, 0, errBadLiteral
		}
		u = u*uint64(base) + uint64(d)
		if u > 1<<40 {
			return 0, 0, errBadLiteral
		}
	}
	if neg {
		v := -int64(u)
		return int64(int32(v)), uint64(uint32(v)), nil
	}
	return int64(int32(uint32(u))), uint64(uint32(u)), nil
}

type litErr string

func (e litErr) Error() string { return string(e) }

const errBadLiteral = litErr("bad literal")

// Site is one traced constant with everything needed for rules, model and explanation.
type Site struct {
	Method       *Method
	Index        int
	Op           string
	Reg          string
	Literal      string
	V            int64
	U            uint64
	Uses         []Use
	Sigs         [][]string
	Wide         bool // 64-bit literal (long/double)
	TraceLimited bool // the bounded normal-CFG trace stopped before exhausting its work
}

func NewSite(m *Method, idx int, resolve Resolver) (*Site, bool) {
	return NewSiteCtx(m, idx, &Ctx{Resolve: resolve})
}

func NewSiteCtx(m *Method, idx int, ctx *Ctx) (*Site, bool) {
	in := m.Insns[idx]
	c := ConstRE.FindStringSubmatch(in.Raw)
	if c == nil {
		return nil, false
	}
	parse := parseLiteral
	if strings.HasPrefix(c[1], "const-wide") {
		parse = parseWide
	}
	v, u, err := parse(c[3])
	if err != nil {
		return nil, false
	}
	s := &Site{Method: m, Index: idx, Op: c[1], Reg: c[2], Literal: c[3], V: v, U: u, Wide: strings.HasPrefix(c[1], "const-wide")}
	s.Uses, s.TraceLimited = m.traceCtx(idx, ctx, 0)
	for _, us := range s.Uses {
		sg := UseSignals(us, v)
		if contains(sg, "ret") && m.Name != "" {
			// the literal is this method's return value: the method's own name says what it is (getMaxCoins → limit)
			for _, t := range camelTokens(m.Name) {
				sg = append(sg, "ret:self:tok:"+t)
			}
		}
		s.Sigs = append(s.Sigs, sg)
	}
	return s, true
}

func opBase(op string) string { return strings.SplitN(op, "/", 2)[0] }

// Features builds the model input. mask >= 0 hides that use (the one that produced the weak label),
// so the model must learn the role from the remaining context instead of copying the labelling rule.
func (s *Site) Features(mask int) []string {
	f := LiteralSignals(s.Literal, s.V, s.U, s.Op)
	m := s.Method
	f = append(f, "ret:"+m.Ret)
	for _, t := range camelTokens(m.Name) {
		f = append(f, "mname:"+t)
	}
	cls := m.Class[strings.LastIndex(m.Class, "/")+1:]
	cls = strings.SplitN(strings.TrimSuffix(cls, ";"), "$", 2)[0]
	for _, t := range camelTokens(cls) {
		f = append(f, "cls:"+t)
	}
	if s.Index+1 < len(m.Insns) {
		f = append(f, "next:"+opBase(m.Insns[s.Index+1].Op))
	}
	if s.Index > 0 {
		f = append(f, "prev:"+opBase(m.Insns[s.Index-1].Op))
	}
	n := 0
	for i, sg := range s.Sigs {
		if i == mask {
			continue
		}
		n++
		for _, x := range sg {
			f = append(f, "u:"+x)
		}
	}
	if n > 4 {
		n = 4
	}
	f = append(f, "nuses:"+itoa(n))
	seen := map[string]bool{}
	out := f[:0]
	for _, x := range f {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
