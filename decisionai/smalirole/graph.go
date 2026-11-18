package smalirole

import (
	"strings"

	"decisionai/gnn"
)

// Graph view of a const site for the GNN: the const node (literal + method context), one node per
// traced use (its signals), the instruction that follows each use, and the ±2 instruction window
// around the const. mask hides one use (the one that produced the weak label) for honest training.

const (
	sgConstUse = iota
	sgConstUseVia
	sgUseConst
	sgUseNext
	sgUsePrev
	sgUseCtx
	sgCtxUse
	sgWin
	sgWinBack
	SiteRelations
)

func (s *Site) Graph(mask int) *gnn.Graph {
	g := &gnn.Graph{}
	add := func(f []string) int {
		g.Feats = append(g.Feats, f)
		return len(g.Feats) - 1
	}
	m := s.Method
	cf := LiteralSignals(s.Literal, s.V, s.U, s.Op)
	cf = append(cf, "CONST", "ret:"+m.Ret)
	for _, t := range camelTokens(m.Name) {
		cf = append(cf, "mname:"+t)
	}
	cls := m.Class[strings.LastIndex(m.Class, "/")+1:]
	cls = strings.SplitN(strings.TrimSuffix(cls, ";"), "$", 2)[0]
	for _, t := range camelTokens(cls) {
		cf = append(cf, "cls:"+t)
	}
	n := len(s.Sigs)
	if mask >= 0 {
		n--
	}
	cf = append(cf, "nuses:"+itoa(min(n, 4)))
	c := add(cf)
	g.Targets = []int{c}
	for d := -2; d <= 2; d++ {
		j := s.Index + d
		if d == 0 || j < 0 || j >= len(m.Insns) {
			continue
		}
		w := add(insnFeats(m.Insns[j], "win"+itoa(d+2)))
		g.Edges = append(g.Edges, gnn.Edge{Src: w, Dst: c, Type: sgWin}, gnn.Edge{Src: c, Dst: w, Type: sgWinBack})
	}
	prev := -1
	for i, u := range s.Uses {
		if i == mask {
			continue
		}
		f := append([]string{"USE", "depth:" + itoa(u.Depth)}, s.Sigs[i]...)
		un := add(f)
		t := sgConstUse
		if u.Depth > 0 {
			t = sgConstUseVia
		}
		g.Edges = append(g.Edges, gnn.Edge{Src: c, Dst: un, Type: t}, gnn.Edge{Src: un, Dst: c, Type: sgUseConst})
		if prev >= 0 {
			g.Edges = append(g.Edges, gnn.Edge{Src: prev, Dst: un, Type: sgUseNext}, gnn.Edge{Src: un, Dst: prev, Type: sgUsePrev})
		}
		prev = un
		// what happens right after the use (in its own method)
		if u.Depth == 0 {
			for k, in := range m.Insns {
				if in.Line == u.Insn.Line && k+1 < len(m.Insns) {
					x := add(insnFeats(m.Insns[k+1], "after"))
					g.Edges = append(g.Edges, gnn.Edge{Src: x, Dst: un, Type: sgCtxUse}, gnn.Edge{Src: un, Dst: x, Type: sgUseCtx})
					break
				}
			}
		}
	}
	return g
}

func insnFeats(in Insn, tag string) []string {
	f := []string{tag, "op:" + opBase(in.Op)}
	if mm := invokeRE.FindStringSubmatch(in.Raw); mm != nil {
		for _, t := range camelTokens(mm[2]) {
			f = append(f, "call:"+t)
		}
	}
	if fr := fieldRE.FindStringSubmatch(in.Raw); fr != nil && !strings.HasPrefix(in.Op, "invoke") {
		for _, t := range camelTokens(fr[1]) {
			f = append(f, "field:"+t)
		}
		f = append(f, "ftype:"+fr[2])
	}
	return f
}
