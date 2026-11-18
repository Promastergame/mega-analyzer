package dataflow

import (
	"sort"
	"strconv"
	"strings"
)

// An array query selects one element, any element (unknown index), or the
// entire array passed to a sink. Exclusions are definite later overwrites on
// ONE CFG path. They must never be shared between alternative branches.
type arrayQuery struct {
	element  bool
	index    int64
	known    bool
	excluded []int64
}

func (q arrayQuery) accepts(index int64) bool {
	if q.known && q.index != index {
		return false
	}
	for _, excluded := range q.excluded {
		if excluded == index {
			return false
		}
	}
	return true
}

func (q arrayQuery) without(index int64) arrayQuery {
	if q.accepts(index) {
		q.excluded = append(append([]int64(nil), q.excluded...), index)
		sort.Slice(q.excluded, func(i, j int) bool { return q.excluded[i] < q.excluded[j] })
	}
	return q
}

func (q arrayQuery) key() string {
	key := strconv.FormatBool(q.element) + ":*"
	if q.known {
		key = strconv.FormatBool(q.element) + ":" + strconv.FormatInt(q.index, 10)
	}
	for _, index := range q.excluded {
		key += "/" + strconv.FormatInt(index, 10)
	}
	return key
}

type arrayOrigin struct {
	index    int // -1 denotes an incoming register
	register string
}

type arrayRefPoint struct {
	method   string
	before   int
	register string
}

type arrayRefSet struct {
	origins  []arrayOrigin
	complete bool
}

// Array reference identity is separate from element contents. A move-object
// creates an alias; new-array creates a distinct allocation even if it reuses
// the same register. Reaching definitions already account for branches.
func (s *sliceState) arrayReferences(signature string, before int, register string, depth int, visiting map[arrayRefPoint]bool) arrayRefSet {
	if register == "" || !s.arrayStep(depth) {
		return arrayRefSet{}
	}
	key := arrayRefPoint{signature, before, register}
	if result, ok := s.arrayRefs[key]; ok {
		return result
	}
	if visiting[key] {
		return arrayRefSet{}
	}
	if visiting == nil {
		visiting = make(map[arrayRefPoint]bool)
	}
	visiting[key] = true
	defer delete(visiting, key)
	defs, complete := s.reachingDefinitions(signature, before, register)
	result := arrayRefSet{complete: complete && !s.cfg(signature).incomplete}
	if defs.entry {
		result.origins = append(result.origins, arrayOrigin{-1, register})
	}
	for _, index := range defs.indices {
		n := s.cfg(signature).nodes[index]
		if n.op == "check-cast" || (strings.HasPrefix(n.op, "move-object") && len(n.fields) >= 3) {
			alias := register
			if n.op != "check-cast" {
				alias = n.fields[2]
			}
			refs := s.arrayReferences(signature, index-1, alias, depth+1, visiting)
			result.origins = append(result.origins, refs.origins...)
			result.complete = result.complete && refs.complete
		} else {
			result.origins = append(result.origins, arrayOrigin{index, register})
		}
	}
	seen := make(map[arrayOrigin]bool)
	out := result.origins[:0]
	for _, origin := range result.origins {
		if !seen[origin] {
			seen[origin] = true
			out = append(out, origin)
		}
	}
	result.origins = out
	// Do not memoize a cycle cut or an exhausted query as a proof of identity.
	if result.complete && !s.sliceStopped() {
		if s.arrayRefs == nil {
			s.arrayRefs = make(map[arrayRefPoint]arrayRefSet)
		}
		s.arrayRefs[key] = result
	}
	return result
}

func (s *sliceState) arrayStep(depth int) bool {
	if s.sliceStopped() {
		return false
	}
	limit := s.maxDepth
	if limit <= 0 {
		limit = maxSliceDepth
	}
	if depth > limit {
		s.truncated, s.sinkTruncated = true, true
		return false
	}
	s.steps++
	s.sinkSteps++
	return true
}

func (s *sliceState) traceCallArgument(signature string, before int, call invokeCall, param, depth int) []sliceHit {
	register := callArgumentRegister(call, param)
	types := paramDescriptors(call.params)
	if param >= 0 && param < len(types) && strings.HasPrefix(types[param], "[") {
		return s.traceArrayRegister(signature, before, register, arrayQuery{}, depth)
	}
	return s.traceRegister(signature, before, register, depth)
}

func (s *sliceState) traceCallValues(signature string, before int, call invokeCall, depth int) []sliceHit {
	var hits []sliceHit
	if !call.isStatic && len(call.registers) > 0 {
		hits = append(hits, s.traceRegister(signature, before, call.registers[0], depth)...)
	}
	for param := range paramDescriptors(call.params) {
		if s.sliceStopped() {
			break
		}
		hits = append(hits, s.traceCallArgument(signature, before, call, param, depth)...)
	}
	return hits
}

func (s *sliceState) traceArrayRegister(signature string, before int, register string, query arrayQuery, depth int) []sliceHit {
	if register == "" || !s.arrayStep(depth) {
		return nil
	}
	key := "array\x00" + signature + "\x00" + strconv.Itoa(before) + "\x00" + register + "\x00" + query.key()
	if _, seen := s.visited[key]; seen {
		return nil
	}
	s.visited[key] = struct{}{}
	defer delete(s.visited, key)
	refs := s.arrayReferences(signature, before, register, depth, nil)
	var hits []sliceHit
	for _, origin := range refs.origins {
		if s.sliceStopped() {
			break
		}
		hits = append(hits, s.traceArrayOrigin(signature, before, origin, query, depth)...)
	}
	for i := range hits {
		hits[i].field = true // array memory is a conservative abstraction
	}
	return uniqueSliceHits(hits)
}

func (s *sliceState) traceArrayOrigin(signature string, before int, origin arrayOrigin, query arrayQuery, depth int) []sliceHit {
	g := s.cfg(signature)
	method := s.methods[signature]
	var hits []sliceHit
	if g.incomplete {
		// An incomplete CFG cannot justify a strong overwrite. Keep all possible
		// writes and the initial value; the existing coverage stats mark it partial.
		for _, id := range g.order {
			if !s.arrayStep(depth) {
				break
			}
			written, _, _ := s.arrayWrite(signature, id, origin, query, depth)
			hits = append(hits, written...)
		}
		return append(hits, s.traceArrayInitial(signature, origin, query, depth+1)...)
	}
	point := before + 1
	if point < 0 {
		point = 0
	}
	if point >= len(g.next) {
		point = len(g.next) - 1
	}
	read := g.next[point]
	type state struct {
		index int
		query arrayQuery
	}
	var queue []state
	if read < 0 {
		for _, id := range g.order {
			if g.reachable[id] && len(g.nodes[id].succ) == 0 {
				queue = append(queue, state{id, query})
			}
		}
	} else if g.reachable[read] {
		for _, pred := range g.nodes[read].pred {
			queue = append(queue, state{pred, query})
		}
		if read == g.order[0] || g.entryHandlers[read] {
			queue = append(queue, state{-1, query})
		}
	}
	seen := make(map[string]bool)
	for len(queue) > 0 {
		item := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		key := strconv.Itoa(item.index) + ":" + item.query.key()
		if seen[key] {
			continue
		}
		seen[key] = true
		if !s.arrayStep(depth) {
			break
		}
		if item.index == origin.index {
			hits = append(hits, s.traceArrayInitial(signature, origin, item.query, depth+1)...)
			continue
		}
		if item.index < 0 || !g.reachable[item.index] {
			continue
		}
		written, index, strong := s.arrayWrite(signature, item.index, origin, item.query, depth)
		hits = append(hits, written...)
		if strong {
			if item.query.known {
				continue // this exact element was definitely replaced on this path
			}
			item.query = item.query.without(index)
		}
		n := g.nodes[item.index]
		for _, pred := range n.pred {
			queue = append(queue, state{pred, item.query})
		}
		if item.index == g.order[0] || g.entryHandlers[item.index] {
			queue = append(queue, state{-1, item.query})
		}
	}
	return addPropagationStep(hits, signature, method.LineStart+before+1)
}

func (s *sliceState) arrayWrite(signature string, index int, origin arrayOrigin, query arrayQuery, depth int) ([]sliceHit, int64, bool) {
	n := s.cfg(signature).nodes[index]
	if len(n.fields) < 4 || !strings.HasPrefix(n.op, "aput") {
		return nil, 0, false
	}
	refs := s.arrayReferences(signature, index-1, n.fields[2], depth+1, nil)
	match := false
	for _, candidate := range refs.origins {
		match = match || candidate == origin
	}
	if !match {
		return nil, 0, false
	}
	value, known := s.arrayIndex(signature, index-1, n.fields[3], depth+1, nil)
	if known && !query.accepts(value) {
		return nil, 0, false
	}
	hits := s.traceRegister(signature, index-1, n.fields[1], depth+1)
	hits = addPropagationStep(hits, signature, s.methods[signature].LineStart+index)
	return hits, value, known && refs.complete && len(refs.origins) == 1
}

// Indices are constant only if ALL reaching definitions agree. Textually
// nearest constants are unsound at joins; numeric parsing also makes 1 == 0x1.
func (s *sliceState) arrayIndex(signature string, before int, register string, depth int, visiting map[arrayRefPoint]bool) (int64, bool) {
	if !s.arrayStep(depth) {
		return 0, false
	}
	key := arrayRefPoint{signature, before, register}
	if visiting[key] {
		return 0, false
	}
	if visiting == nil {
		visiting = make(map[arrayRefPoint]bool)
	}
	visiting[key] = true
	defer delete(visiting, key)
	defs, complete := s.reachingDefinitions(signature, before, register)
	if !complete || defs.entry || len(defs.indices) == 0 || s.cfg(signature).incomplete {
		return 0, false
	}
	var result int64
	for i, index := range defs.indices {
		n := s.cfg(signature).nodes[index]
		if len(n.fields) < 3 {
			return 0, false
		}
		var value int64
		var known bool
		switch n.op {
		case "const", "const/4", "const/16", "const/high16":
			value, err := strconv.ParseInt(n.fields[2], 0, 32)
			if err != nil {
				return 0, false
			}
			if i > 0 && result != value {
				return 0, false
			}
			result = value
			continue
		case "move", "move/from16", "move/16":
			value, known = s.arrayIndex(signature, index-1, n.fields[2], depth+1, visiting)
		}
		if !known || (i > 0 && result != value) {
			return 0, false
		}
		result = value
	}
	return result, true
}

func (s *sliceState) traceArrayInitial(signature string, origin arrayOrigin, query arrayQuery, depth int) []sliceHit {
	if !s.arrayStep(depth) {
		return nil
	}
	if origin.index < 0 {
		return s.traceArrayParameter(signature, origin.register, query, depth)
	}
	method := s.methods[signature]
	n := s.cfg(signature).nodes[origin.index]
	if n.op == "new-array" || strings.HasPrefix(n.op, "const") {
		return nil
	}
	if strings.HasPrefix(n.op, "iget") || strings.HasPrefix(n.op, "sget") {
		var hits []sliceHit
		for _, write := range s.fieldWrites[n.fields[len(n.fields)-1]] {
			if s.sliceStopped() {
				break
			}
			hits = append(hits, s.traceArrayRegister(write.method, write.line-1, write.register, query, depth+1)...)
		}
		return addPropagationStep(hits, signature, method.LineStart+origin.index)
	}
	if n.op == "move-result-object" {
		// filled-new-array has a move-result-object just like an invoke, but
		// must not be parsed as a method call.
		for i := origin.index - 1; i >= 0; i-- {
			previous := s.cfg(signature).nodes[i]
			if previous == nil {
				continue
			}
			if previous.op == "filled-new-array" || previous.op == "filled-new-array/range" {
				line := cleanSmali(method.Body[i])
				open, close := strings.IndexByte(line, '{'), strings.IndexByte(line, '}')
				if open < 0 || close < open {
					return nil
				}
				var hits []sliceHit
				for index, reg := range parseRegisterList(line[open+1 : close]) {
					if query.accepts(int64(index)) {
						hits = append(hits, s.traceRegister(signature, i-1, reg, depth+1)...)
					}
				}
				return addPropagationStep(hits, signature, method.LineStart+i)
			}
			break
		}
		callIndex, call, ok := previousInvoke(method.Body, origin.index-1)
		if ok && !s.isNativeMethod(call.signature) {
			if _, source := sourceFor(call.signature); !source {
				if callees := s.resolveCallees(call); len(callees) > 0 {
					var hits []sliceHit
					for _, callee := range callees {
						hits = append(hits, s.traceArrayReturns(s.methods[callee], query, depth+1)...)
					}
					return s.bindCalleeParams(signature, callIndex-1, call, hits, depth+1)
				}
			}
		}
	}
	hits := s.traceDefinition(signature, method, origin.index, origin.register, depth)
	if query.element {
		for i := range hits {
			hits[i].valueType = strings.TrimPrefix(hits[i].valueType, "[")
		}
	}
	return hits
}

func (s *sliceState) traceArrayParameter(signature, register string, query arrayQuery, depth int) []sliceHit {
	method := s.methods[signature]
	param, ok := parameterForRegister(method, register)
	if !ok {
		return nil
	}
	for _, seed := range entryPointTaints(method) {
		if seed.param == param {
			return []sliceHit{{source: signature + " " + entryPointLabel(signature, s.exportedComponents), labels: seed.labels, param: -1,
				steps: []Step{{Method: signature, Type: "source", Line: method.LineStart}}, field: true}}
		}
	}
	if s.returnScopes[signature] == 0 {
		var hits []sliceHit
		for _, ref := range s.callers[signature] {
			if s.sliceStopped() {
				break
			}
			if !s.reachableInstruction(ref.caller, ref.index) {
				continue
			}
			reg := callArgumentRegister(ref.call, param)
			hits = append(hits, addPropagationStep(s.traceArrayRegister(ref.caller, ref.index-1, reg, query, depth+1),
				ref.caller, s.methods[ref.caller].LineStart+ref.index)...)
		}
		if len(hits) > 0 {
			return hits
		}
	}
	return []sliceHit{{param: param, array: &query}}
}

func (s *sliceState) traceArrayReturns(method methodData, query arrayQuery, depth int) []sliceHit {
	if !s.arrayStep(depth) {
		return nil
	}
	if s.returnScopes == nil {
		s.returnScopes = make(map[string]int)
	}
	s.returnScopes[method.Signature]++
	defer func() { s.returnScopes[method.Signature]-- }()
	var hits []sliceHit
	for index, raw := range method.Body {
		fields := smaliFields(cleanSmali(raw))
		if len(fields) >= 2 && fields[0] == "return-object" && s.reachableInstruction(method.Signature, index) {
			hits = append(hits, addSliceStep(s.traceArrayRegister(method.Signature, index-1, fields[1], query, depth+1),
				Step{Method: method.Signature, Type: "return", Line: method.LineStart + index})...)
		}
	}
	return hits
}
