package dataflow

import (
	"context"
	"sort"
	"strconv"
	"strings"
)

// Local instruction IR and conservative control-flow graph. This computes
// reaching definitions, not SMT/path feasibility or a whole-program SSA form.
type cfgInstruction struct {
	index, pc, units int
	op               string
	fields           []string
	call             *invokeCall
	pred, succ       []int
}
type cfgPayload struct {
	pc, raw      int
	kind         string
	targets      []string
	count, width int
}
type defPoint struct {
	read     int
	register string
}
type defSet struct {
	indices []int
	entry   bool
}
type methodCFG struct {
	nodes         map[int]*cfgInstruction
	order         []int
	next          []int
	reachable     map[int]bool
	definitions   map[defPoint]defSet
	incomplete    bool
	entryHandlers map[int]bool
	edges         int
}

func buildMethodCFG(method methodData, ctx context.Context) *methodCFG {
	if ctx == nil {
		ctx = context.Background()
	}
	g := &methodCFG{nodes: map[int]*cfgInstruction{}, reachable: map[int]bool{}, definitions: map[defPoint]defSet{}}
	g.entryHandlers = map[int]bool{}
	rawLabels := map[string]int{}
	labels := map[string]int{}
	labelPC := map[string]int{}
	pcNodes := map[int]int{}
	payloads := map[int]*cfgPayload{}
	var payload *cfgPayload
	var catches []string
	pc, annotation := 0, 0
	for i, raw := range method.Body {
		if len(g.order) >= 50000 || (i&255 == 0 && ctx.Err() != nil) {
			g.incomplete = true
			break
		}
		line := cleanSmali(raw)
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == ".annotation" || f[0] == ".subannotation" || strings.Contains(line, "= .subannotation") {
			annotation++
			continue
		}
		if len(f) > 1 && f[0] == ".end" && (f[1] == "annotation" || f[1] == "subannotation") {
			if annotation > 0 {
				annotation--
			}
			continue
		}
		if annotation > 0 {
			continue
		}
		if payload != nil {
			if len(f) > 1 && f[0] == ".end" && f[1] == payload.kind {
				switch payload.kind {
				case "packed-switch":
					pc += 4 + 2*payload.count
				case "sparse-switch":
					pc += 2 + 4*payload.count
				case "array-data":
					pc += 4 + (payload.width*payload.count+1)/2
				}
				payload = nil
				continue
			}
			if payload.kind == "array-data" {
				payload.count += len(strings.Fields(strings.ReplaceAll(line, ",", " ")))
			} else {
				payload.targets = append(payload.targets, strings.TrimSuffix(f[len(f)-1], ","))
				payload.count++
			}
			continue
		}
		if strings.HasPrefix(f[0], ":") {
			if _, exists := rawLabels[f[0]]; exists && labelPC[f[0]] != pc {
				g.incomplete = true
			}
			rawLabels[f[0]] = i
			labelPC[f[0]] = pc
			continue
		}
		if f[0] == ".packed-switch" || f[0] == ".sparse-switch" || f[0] == ".array-data" {
			payload = &cfgPayload{pc: pc, raw: i, kind: strings.TrimPrefix(f[0], ".")}
			payloads[pc] = payload
			if payload.kind == "array-data" {
				if len(f) > 1 {
					n, e := strconv.ParseInt(f[1], 0, 32)
					if e == nil && (n == 1 || n == 2 || n == 4 || n == 8) {
						payload.width = int(n)
					} else {
						g.incomplete = true
					}
				} else {
					g.incomplete = true
				}
			}
			continue
		}
		if f[0] == ".catch" || f[0] == ".catchall" {
			catches = append(catches, line)
			continue
		}
		if strings.HasPrefix(f[0], ".") {
			continue
		}
		units, ok := cfgOpcodeUnits[f[0]]
		if !ok {
			g.incomplete = true
			units = 1
		}
		n := &cfgInstruction{index: i, pc: pc, units: units, op: f[0], fields: smaliFields(line)}
		if call, ok := parseInvoke(line); ok {
			n.call = &call
		}
		g.nodes[i] = n
		g.order = append(g.order, i)
		pcNodes[pc] = i
		pc += units
	}
	if payload != nil || annotation != 0 {
		g.incomplete = true
	}
	g.next = make([]int, len(method.Body)+1)
	next := -1
	for i := len(method.Body); i >= 0; i-- {
		if _, ok := g.nodes[i]; ok {
			next = i
		}
		g.next[i] = next
	}
	for label, raw := range rawLabels {
		labels[label] = g.next[raw]
	}
	edgeSet := map[[2]int]bool{}
	addEdge := func(from, to int) {
		if g.edges >= 200000 || ctx.Err() != nil {
			g.incomplete = true
			return
		}
		a, b := g.nodes[from], g.nodes[to]
		if a == nil || b == nil {
			g.incomplete = true
			return
		}
		key := [2]int{from, to}
		if edgeSet[key] {
			return
		}
		edgeSet[key] = true
		a.succ = append(a.succ, to)
		b.pred = append(b.pred, from)
		g.edges++
	}
	target := func(token string, base int) (int, bool) {
		token = strings.TrimSuffix(token, ",")
		if strings.HasPrefix(token, ":") {
			n, ok := labels[token]
			return n, ok && n >= 0
		}
		// The built-in DEX emitter renders branch immediates in signed decimal,
		// and payload offsets in hex. Both are relative Dalvik CODE UNIT offsets.
		v, e := cfgRelativeOffset(token)
		if e != nil {
			return 0, false
		}
		n, ok := pcNodes[base+int(v)]
		return n, ok
	}
	for j, id := range g.order {
		n := g.nodes[id]
		f := n.fields
		fall := func() {
			if j+1 < len(g.order) {
				other := g.nodes[g.order[j+1]]
				if other.pc != n.pc+n.units {
					g.incomplete = true
				}
				addEdge(id, other.index)
			}
		}
		jump := func(token string) {
			if to, ok := target(token, n.pc); ok {
				addEdge(id, to)
			} else {
				g.incomplete = true
			}
		}
		switch {
		case strings.HasPrefix(n.op, "return") || n.op == "throw":
		case strings.HasPrefix(n.op, "goto"):
			if len(f) > 1 {
				jump(f[len(f)-1])
			} else {
				g.incomplete = true
			}
		case strings.HasPrefix(n.op, "if-"):
			fall()
			if len(f) > 1 {
				jump(f[len(f)-1])
			} else {
				g.incomplete = true
			}
		case n.op == "packed-switch" || n.op == "sparse-switch":
			fall()
			if len(f) < 3 {
				g.incomplete = true
				continue
			}
			token := f[len(f)-1]
			where, ok := labelPC[token]
			if !ok {
				offset, e := cfgRelativeOffset(token)
				if e == nil {
					where = n.pc + int(offset)
					ok = true
				}
			}
			p := payloads[where]
			if !ok || p == nil || p.kind != n.op {
				g.incomplete = true
				continue
			}
			for _, to := range p.targets {
				jump(to)
			}
		default:
			fall()
		}
	}
	// Include exceptional successors conservatively. No claim that every
	// instruction actually throws, or that all combinations of edges are feasible.
	// Exception handlers may see state BEFORE a throwing instruction commits
	// its destination. Preserve both pre/post states conservatively. Original
	// predecessor snapshots avoid manufacturing cascading exception edges.
	normalPred := map[int][]int{}
	for id, n := range g.nodes {
		normalPred[id] = append([]int(nil), n.pred...)
	}
	for _, line := range catches {
		if g.edges >= 200000 || ctx.Err() != nil {
			g.incomplete = true
			break
		}
		open, close := strings.IndexByte(line, '{'), strings.IndexByte(line, '}')
		if open < 0 || close < open {
			g.incomplete = true
			continue
		}
		bounds := strings.Split(line[open+1:close], "..")
		after := strings.Fields(line[close+1:])
		if len(bounds) != 2 || len(after) == 0 {
			g.incomplete = true
			continue
		}
		start, ok1 := rawLabels[strings.TrimSpace(bounds[0])]
		end, ok2 := rawLabels[strings.TrimSpace(bounds[1])]
		dest, ok3 := labels[after[0]]
		if !ok1 || !ok2 || !ok3 || dest < 0 || end < start {
			g.incomplete = true
			continue
		}
		for j, id := range g.order {
			if j&255 == 0 && ctx.Err() != nil {
				g.incomplete = true
				break
			}
			if id >= start && id < end {
				addEdge(id, dest)
				for _, pred := range normalPred[id] {
					addEdge(pred, dest)
				}
				if id == g.order[0] {
					g.entryHandlers[dest] = true
				}
			}
		}
	}
	if len(g.order) > 0 {
		queue := []int{g.order[0]}
		for len(queue) > 0 {
			id := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			if g.reachable[id] {
				continue
			}
			g.reachable[id] = true
			queue = append(queue, g.nodes[id].succ...)
		}
	}
	return g
}

func modeledReceiverMutation(call invokeCall) bool {
	for _, prefix := range []string{
		"Ljava/io/File;-><init>",
		"Ljava/lang/StringBuilder;-><init>", "Ljava/lang/StringBuilder;->append",
		"Ljava/lang/StringBuffer;-><init>", "Ljava/lang/StringBuffer;->append",
	} {
		if methodMatches(prefix, call.signature) {
			return !call.isStatic && len(call.registers) > 0
		}
	}
	return false
}
func (n *cfgInstruction) defines(register string) bool {
	if n.call != nil && modeledReceiverMutation(*n.call) && n.call.registers[0] == register {
		return true
	}
	return len(n.fields) > 1 && n.fields[1] == register && definesRegister(n.op)
}
func (s *sliceState) cfg(signature string) *methodCFG {
	if s.cfgs == nil {
		s.cfgs = map[string]*methodCFG{}
	}
	if g := s.cfgs[signature]; g != nil {
		return g
	}
	g := buildMethodCFG(s.methods[signature], s.ctx)
	s.cfgs[signature] = g
	s.cfgNodes += len(g.order)
	s.cfgEdges += g.edges
	if g.incomplete {
		s.cfgIncomplete++
	}
	return g
}
func (s *sliceState) reachableInstruction(signature string, index int) bool {
	g := s.cfg(signature)
	return g.incomplete || g.reachable[index]
}

func (s *sliceState) reachingDefinitions(signature string, before int, register string) (defSet, bool) {
	g := s.cfg(signature)
	point := before + 1
	if point < 0 {
		point = 0
	}
	if point >= len(g.next) {
		point = len(g.next) - 1
	}
	read := g.next[point]
	key := defPoint{read: read, register: register}
	if answer, ok := g.definitions[key]; ok {
		s.cfgCacheHits++
		return answer, true
	}
	answer := defSet{}
	if g.incomplete {
		// Never turn an unsupported graph into a proof of safety: all definitions
		// and the entry parameter remain possible, and coverage is flagged partial.
		answer.entry = true
		for _, id := range g.order {
			if s.sliceStopped() {
				return answer, false
			}
			s.steps++
			s.sinkSteps++
			s.cfgQueries++
			if g.nodes[id].defines(register) {
				answer.indices = append(answer.indices, id)
			}
		}
	} else if len(g.order) > 0 {
		var queue []int
		if read < 0 {
			for _, id := range g.order {
				if len(g.nodes[id].succ) == 0 && g.reachable[id] {
					queue = append(queue, id)
				}
			}
		} else {
			if !g.reachable[read] {
				return answer, true
			}
			queue = append(queue, g.nodes[read].pred...)
			answer.entry = read == g.order[0] || g.entryHandlers[read]
		}
		seen := map[int]bool{}
		for len(queue) > 0 {
			id := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			if seen[id] || !g.reachable[id] {
				continue
			}
			seen[id] = true
			if s.sliceStopped() {
				return answer, false
			}
			s.steps++
			s.sinkSteps++
			s.cfgQueries++
			n := g.nodes[id]
			if n.defines(register) {
				answer.indices = append(answer.indices, id)
				continue
			}
			if id == g.order[0] || g.entryHandlers[id] {
				answer.entry = true
			}
			queue = append(queue, n.pred...)
		}
	}
	sort.Ints(answer.indices)
	g.definitions[key] = answer
	return answer, true
}

func uniqueSliceHits(in []sliceHit) []sliceHit {
	if len(in) < 2 {
		return in
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, h := range in {
		origin := ""
		if len(h.steps) > 0 {
			origin = h.steps[0].Method + ":" + strconv.Itoa(h.steps[0].Line)
		}
		key := h.valueType + "\x00" + h.source + "\x00" + origin + "\x00" + strconv.Itoa(h.param) + ":" + strconv.FormatUint(uint64(h.labels), 10) + ":" + strconv.Itoa(int(h.sanitized)) + ":" + strconv.FormatBool(h.field)
		if h.array != nil {
			key += "\x00" + h.array.key()
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, h)
		}
	}
	return out
}

// DEX Fmt31t can render a negative displacement as unsigned 32-bit hex.
func cfgRelativeOffset(token string) (int64, error) {
	n, e := strconv.ParseInt(token, 0, 32)
	if e != nil && strings.HasPrefix(token, "0x") {
		u, err := strconv.ParseUint(token, 0, 32)
		if err == nil {
			return int64(int32(u)), nil
		}
	}
	return n, e
}
