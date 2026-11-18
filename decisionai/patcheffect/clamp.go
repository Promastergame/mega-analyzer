package patcheffect

import (
	"regexp"
	"strconv"
	"strings"

	"decisionai/smalirole"
)

var constValRE = regexp.MustCompile(`^const(?:/4|/16|/high16)?\s+([vp]\d+)\s*,\s*(-?(?:0x[0-9a-fA-F]+|\d+))$`)
var mathMinMaxRE = regexp.MustCompile(`invoke-static\s*\{([vp]\d+)\s*,\s*([vp]\d+)\}\s*,\s*Ljava/lang/Math;->(min|max)\(II\)I`)
var coerceRE = regexp.MustCompile(`Lkotlin/ranges/RangesKt[^;]*;->coerce(AtMost|AtLeast)\(II\)I`)

// Clamp describes a bound that limits the patched value further down the method.
type Clamp struct {
	Line  int    `json:"line"`
	Kind  string `json:"kind"` // upper | lower
	Bound int64  `json:"bound"`
	How   string `json:"how"`
}

func lit(s string) (int64, bool) {
	neg := strings.HasPrefix(s, "-")
	t := strings.TrimPrefix(s, "-")
	base := 10
	if strings.HasPrefix(t, "0x") {
		base, t = 16, t[2:]
	}
	u, err := strconv.ParseInt(t, base, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		u = -u
	}
	return int64(int32(u)), true
}

// constBefore finds a register's constant value written shortly before insn i (straight-line, best effort).
func constBefore(m *smalirole.Method, i int, reg string) (int64, bool) {
	for j := i - 1; j >= 0 && j > i-16; j-- {
		in := m.Insns[j]
		if len(in.Regs) > 0 && in.Regs[0] == reg {
			if c := constValRE.FindStringSubmatch(in.Raw); c != nil && c[1] == reg {
				return lit(c[2])
			}
			return 0, false
		}
	}
	return 0, false
}

// FindClamps detects `if-cmp vA, vB, :skip ; move vA, vB` and Math.min/max / coerceAt* against a constant,
// where vA carries the patched value (or a move-alias of it).
func FindClamps(code string, constLine int) []Clamp {
	m := smalirole.ParseMethod("", code)
	start := -1
	for i, in := range m.Insns {
		if in.Line == constLine {
			start = i
		}
	}
	if start < 0 || len(m.Insns[start].Regs) == 0 {
		return nil
	}
	alias := map[string]bool{m.Insns[start].Regs[0]: true}
	var out []Clamp
	for i := start + 1; i < len(m.Insns); i++ {
		in := m.Insns[i]
		op := in.Op
		switch {
		case strings.HasPrefix(op, "move") && !strings.HasPrefix(op, "move-result") && len(in.Regs) == 2 && alias[in.Regs[1]]:
			alias[in.Regs[0]] = true
			continue
		case (op == "if-le" || op == "if-lt" || op == "if-ge" || op == "if-gt") && len(in.Regs) == 2 && alias[in.Regs[0]] && i+1 < len(m.Insns):
			nx := m.Insns[i+1]
			if strings.HasPrefix(nx.Op, "move") && len(nx.Regs) == 2 && nx.Regs[0] == in.Regs[0] && nx.Regs[1] == in.Regs[1] {
				if b, ok := constBefore(m, i, in.Regs[1]); ok {
					kind := "upper"
					if op == "if-ge" || op == "if-gt" {
						kind = "lower"
					}
					out = append(out, Clamp{Line: in.Line, Kind: kind, Bound: b, How: op + " + move (ручной clamp)"})
				}
			}
		case strings.HasPrefix(op, "invoke-static"):
			if mm := mathMinMaxRE.FindStringSubmatch(in.Raw); mm != nil {
				a, b := mm[1], mm[2]
				other := ""
				if alias[a] {
					other = b
				} else if alias[b] {
					other = a
				}
				if other != "" {
					if bv, ok := constBefore(m, i, other); ok {
						kind := "upper"
						if mm[3] == "max" {
							kind = "lower"
						}
						out = append(out, Clamp{Line: in.Line, Kind: kind, Bound: bv, How: "Math." + mm[3]})
					}
				}
			} else if cm := coerceRE.FindStringSubmatch(in.Raw); cm != nil && len(in.Regs) == 2 && alias[in.Regs[0]] {
				if bv, ok := constBefore(m, i, in.Regs[1]); ok {
					kind := "upper"
					if cm[1] == "AtLeast" {
						kind = "lower"
					}
					out = append(out, Clamp{Line: in.Line, Kind: kind, Bound: bv, How: "coerce" + cm[1]})
				}
			}
		}
		// a write to an aliased register (other than the clamp move handled above) ends tracking for it
		if len(in.Regs) > 0 && alias[in.Regs[0]] && !strings.HasPrefix(op, "if-") && !strings.HasPrefix(op, "invoke") &&
			!strings.HasPrefix(op, "return") && !strings.HasPrefix(op, "iput") && !strings.HasPrefix(op, "sput") && !strings.HasPrefix(op, "aput") {
			if !(strings.HasPrefix(op, "move") && len(in.Regs) == 2 && i > 0 && strings.HasPrefix(m.Insns[i-1].Op, "if-")) {
				delete(alias, in.Regs[0])
			}
		}
		if strings.HasPrefix(op, "return") || op == "throw" {
			break
		}
	}
	return out
}

// Effective applies clamps to a value.
func Effective(v int64, cs []Clamp) int64 {
	for _, c := range cs {
		if c.Kind == "upper" && v > c.Bound {
			v = c.Bound
		}
		if c.Kind == "lower" && v < c.Bound {
			v = c.Bound
		}
	}
	return v
}
