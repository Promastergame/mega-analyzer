package smalirole

import (
	"regexp"
	"sort"
	"strings"
)

var invokeRE = regexp.MustCompile(`\}\s*,\s*(L[^;]+;|\[[^-]+)->([^(]+)\(([^)]*)\)(\S+)`)
var fieldRE = regexp.MustCompile(`->([A-Za-z0-9_$]+):(\S+)`)

// Use is one place where the traced value is read.
type Use struct {
	Insn  Insn
	Pos   int    // operand position of the traced register
	Depth int    // 0 = same method, 1 = inside callee
	Via   string // callee name when Depth > 0
	Other string // for comparisons: what the value is compared with ("result:indexOf", "param", …)
}

// Resolver finds an app method by class and name/descriptor (for one-level interprocedural flow).
type Resolver func(class, name, params string) *Method

// FieldRead is one iget/sget of a field somewhere in the app.
type FieldRead struct {
	Method *Method
	Index  int
}

// FieldIndex returns the reads of a field reference "Lcls;->name:Type".
type FieldIndex func(ref string) []FieldRead

// Ctx carries app-wide lookups. Any member may be nil.
type Ctx struct {
	Resolve Resolver
	Fields  FieldIndex
	Writers FieldIndex // iput/sput of a field anywhere in the app
}

var fieldRefRE = regexp.MustCompile(`(L[^;]+;->[A-Za-z0-9_$]+:\S+)`)

const maxFieldReaders = 8

func isDefOp(op string) bool {
	for _, p := range []string{"if-", "invoke-", "iput", "sput", "aput", "return", "throw", "monitor-", "packed-switch", "sparse-switch", "fill-array-data", "check-cast", "filled-new-array"} {
		if strings.HasPrefix(op, p) {
			return false
		}
	}
	return true
}

func (m *Method) succ(i int) []int {
	in := m.Insns[i]
	var s []int
	if strings.HasPrefix(in.Op, "if-") || strings.HasPrefix(in.Op, "goto") {
		f := strings.Fields(in.Raw)
		if t, ok := m.Labels[f[len(f)-1]]; ok {
			s = append(s, t)
		}
	}
	if strings.HasSuffix(in.Op, "-switch") { // all case targets are unknown here: assume any label may follow
		for _, t := range m.Labels {
			s = append(s, t)
		}
		sort.Ints(s) // map order would make traces (and answers) differ run to run
	}
	if !strings.HasPrefix(in.Op, "goto") && !strings.HasPrefix(in.Op, "return") && in.Op != "throw" && i+1 < len(m.Insns) {
		s = append(s, i+1)
	}
	return s
}

// definedBy reports what last wrote register r before index i on the straight-line path (best effort).
func (m *Method) definedBy(i int, r string) string {
	for j := i - 1; j >= 0 && j > i-12; j-- {
		in := m.Insns[j]
		if len(in.Regs) > 0 && in.Regs[0] == r && isDefOp(in.Op) {
			if strings.HasPrefix(in.Op, "move-result") && j > 0 {
				if mm := invokeRE.FindStringSubmatch(m.Insns[j-1].Raw); mm != nil {
					return "result:" + mm[2]
				}
			}
			if strings.HasPrefix(in.Op, "const") {
				return "const"
			}
			if strings.HasPrefix(in.Op, "iget") || strings.HasPrefix(in.Op, "sget") {
				if f := fieldRE.FindStringSubmatch(in.Raw); f != nil {
					return "field:" + f[1]
				}
			}
			return in.Op
		}
	}
	if strings.HasPrefix(r, "p") {
		return "param"
	}
	return ""
}

// Trace follows the value written at insn index start through the CFG with move-aliases.
func (m *Method) Trace(start int, resolve Resolver, depth int) []Use {
	return m.TraceCtx(start, &Ctx{Resolve: resolve}, depth)
}

// TraceCtx is Trace with field-flow: a value stored to a field is followed to every read of that field.
func (m *Method) TraceCtx(start int, ctx *Ctx, depth int) []Use {
	uses, _ := m.traceCtx(start, ctx, depth)
	return uses
}

func (m *Method) traceCtx(start int, ctx *Ctx, depth int) ([]Use, bool) {
	var resolve Resolver
	if ctx != nil {
		resolve = ctx.Resolve
	}
	if start < 0 || start >= len(m.Insns) || len(m.Insns[start].Regs) == 0 {
		return nil, false
	}
	wide := strings.Contains(m.Insns[start].Op, "-wide")
	type state struct {
		pc    int
		alias string
	}
	var uses []Use
	seenUse := map[int]bool{}
	seen := map[state]bool{}
	var work []state
	for _, n := range m.succ(start) {
		work = append(work, state{n, m.Insns[start].Regs[0]})
	}
	for steps := 0; len(work) > 0 && steps < 4000; steps++ {
		st := work[len(work)-1]
		work = work[:len(work)-1]
		if seen[st] || st.pc >= len(m.Insns) {
			continue
		}
		seen[st] = true
		al := map[string]bool{}
		for _, a := range strings.Split(st.alias, ",") {
			al[a] = true
		}
		in := m.Insns[st.pc]
		src := 0
		if isDefOp(in.Op) && !strings.HasSuffix(in.Op, "/2addr") {
			src = 1
		}
		used := -1
		for k := src; k < len(in.Regs); k++ {
			if al[in.Regs[k]] {
				used = k
				break
			}
		}
		if used >= 0 && !seenUse[st.pc] {
			seenUse[st.pc] = true
			u := Use{Insn: in, Pos: used}
			if strings.HasPrefix(in.Op, "if-") && len(in.Regs) == 2 {
				u.Other = m.definedBy(st.pc, in.Regs[1-used])
			}
			uses = append(uses, u)
			if ctx != nil && ctx.Fields != nil && depth == 0 && used == 0 && (strings.HasPrefix(in.Op, "iput") || strings.HasPrefix(in.Op, "sput")) {
				if fr := fieldRefRE.FindStringSubmatch(in.Raw); fr != nil {
					reads := ctx.Fields(fr[1])
					for k, rd := range reads {
						if k == maxFieldReaders {
							break
						}
						sub := rd.Method.TraceCtx(rd.Index, &Ctx{Resolve: resolve}, 1)
						name := fr[1][strings.Index(fr[1], "->")+2:]
						for j := range sub {
							sub[j].Depth, sub[j].Via = 1, "поле "+name+" в "+rd.Method.Name
						}
						uses = append(uses, sub...)
					}
				}
			}
			if resolve != nil && depth == 0 && strings.HasPrefix(in.Op, "invoke") {
				if mm := invokeRE.FindStringSubmatch(in.Raw); mm != nil {
					if callee := resolve(mm[1], mm[2], mm[3]); callee != nil {
						uses = append(uses, callee.traceParam(in, used, mm[2], resolve)...)
					}
				}
			}
		}
		if isDefOp(in.Op) && len(in.Regs) > 0 {
			d := in.Regs[0]
			if strings.HasPrefix(in.Op, "move") && !strings.HasPrefix(in.Op, "move-result") && len(in.Regs) > 1 && al[in.Regs[1]] {
				al[d] = true
			} else {
				delete(al, d)
				if strings.Contains(in.Op, "-wide") && !wide { // wide write clobbers d+1 too
					delete(al, d[:1]+itoa(atoi(d[1:])+1))
				}
			}
		}
		if len(al) == 0 {
			continue
		}
		keys := make([]string, 0, len(al))
		for k := range al {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, n := range m.succ(st.pc) {
			work = append(work, state{n, strings.Join(keys, ",")})
		}
	}
	return uses, len(work) > 0
}

// traceParam continues a trace inside the callee from the parameter that received the value.
func (callee *Method) traceParam(call Insn, pos int, name string, resolve Resolver) []Use {
	argIdx := pos
	if !strings.HasPrefix(call.Op, "invoke-static") {
		argIdx-- // skip receiver
	}
	if argIdx < 0 {
		return nil
	}
	// wide arguments occupy two registers in the call list
	decl, slot := -1, 0
	for i, p := range callee.Params {
		if slot == argIdx {
			decl = i
			break
		}
		slot++
		if p == "J" || p == "D" {
			slot++
		}
	}
	if decl < 0 {
		return nil
	}
	reg := callee.ParamRegister(decl)
	fake := &Method{Class: callee.Class, Name: callee.Name, Params: callee.Params, Ret: callee.Ret, Static: callee.Static, Labels: map[string]int{}}
	fake.Insns = append([]Insn{{Line: 0, Op: "const", Regs: []string{reg}, Raw: "const " + reg + ", <arg>"}}, callee.Insns...)
	for k, v := range callee.Labels {
		fake.Labels[k] = v + 1
	}
	us := fake.Trace(0, nil, 1)
	for i := range us {
		us[i].Depth, us[i].Via = 1, callee.Class+"->"+name
	}
	return us
}
