package dataflow

import (
	"fmt"
	"strings"
)

// Alias mutations and opaque callees must not leave a stale constant builder
// or array value in a source proof. The taint engine's direct receiver model
// is reused; operations through another alias conservatively require review.
func (in *sourceInspector) unsupportedObjectMutation(signature string, before int, register string) bool {
	g := in.state.cfg(signature)
	origins, complete := in.objectOrigins(signature, before, register, 0, map[string]bool{})
	if !complete || len(origins) == 0 {
		return true
	}
	point := before + 1
	if point < 0 {
		point = 0
	}
	if point >= len(g.next) {
		return true
	}
	read := g.next[point]
	if read < 0 {
		return true
	}
	reachesRead := map[int]bool{}
	queue := append([]int(nil), g.nodes[read].pred...)
	for len(queue) > 0 {
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if reachesRead[id] || !g.reachable[id] {
			continue
		}
		if in.state.sliceStopped() {
			return true
		}
		in.state.steps++
		in.state.sinkSteps++
		reachesRead[id] = true
		queue = append(queue, g.nodes[id].pred...)
	}
	for _, id := range g.order {
		node := g.nodes[id]
		if !reachesRead[id] {
			continue
		}
		// Array writes are not approximated as the original filled-new-array.
		if strings.HasPrefix(node.op, "aput") && len(node.fields) >= 3 {
			ids, _ := in.objectOrigins(signature, id-1, node.fields[2], 0, map[string]bool{})
			if intersectsSourceOrigins(origins, ids) {
				in.cite(signature, id)
				return true
			}
		}
		if node.call == nil {
			continue
		}
		call := *node.call
		for argument, reg := range call.registers {
			ids, _ := in.objectOrigins(signature, id-1, reg, 0, map[string]bool{})
			if !intersectsSourceOrigins(origins, ids) {
				continue
			}
			if argument == 0 && !call.isStatic {
				if sourceReadOnlyObjectCall(call.signature) {
					continue
				}
				if modeledReceiverMutation(call) && reg == register {
					continue
				}
			}
			in.cite(signature, id)
			return true
		}
	}
	return false
}

func sourceReadOnlyObjectCall(signature string) bool {
	switch signature {
	case "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;",
		"Ljava/lang/StringBuffer;->toString()Ljava/lang/String;",
		"Ljava/io/File;->getAbsolutePath()Ljava/lang/String;",
		"Ljava/io/File;->getPath()Ljava/lang/String;",
		"Ljava/io/File;->exists()Z", "Ljava/io/File;->isDirectory()Z",
		"Ljava/io/File;->listFiles()[Ljava/io/File;", "Ljava/io/File;->mkdirs()Z":
		return true
	}
	return false
}

func intersectsSourceOrigins(a, b map[int]bool) bool {
	for id := range a {
		if b[id] {
			return true
		}
	}
	return false
}

// objectOrigins identifies local allocations, including move-object aliases
// and append's returned receiver. Unknown/native/parameter-owned objects are
// deliberately not promoted to an allocation with known mutation history.
func (in *sourceInspector) objectOrigins(signature string, before int, register string, depth int, visiting map[string]bool) (map[int]bool, bool) {
	s := in.state
	if depth > 24 || s.sliceStopped() || register == "" {
		return nil, false
	}
	s.steps++
	s.sinkSteps++
	key := fmt.Sprintf("%d:%s", before, register)
	if visiting[key] {
		return nil, false
	}
	visiting[key] = true
	defer delete(visiting, key)
	defs, complete := s.reachingDefinitions(signature, before, register)
	if !complete || defs.entry || len(defs.indices) == 0 {
		return nil, false
	}
	out := map[int]bool{}
	g := s.cfg(signature)
	for _, id := range defs.indices {
		node := g.nodes[id]
		if node == nil {
			return nil, false
		}
		f := node.fields
		alias := ""
		switch {
		case node.op == "new-instance" || node.op == "new-array":
			out[id] = true
			continue
		case node.call != nil && modeledReceiverMutation(*node.call):
			alias = register
		case node.op == "move-object" || node.op == "move-object/from16" || node.op == "move-object/16":
			if len(f) < 3 {
				return nil, false
			}
			alias = f[2]
		case strings.HasPrefix(node.op, "move-result"):
			previous := in.previousNode(signature, id)
			if previous == nil {
				return nil, false
			}
			if strings.HasPrefix(previous.op, "filled-new-array") ||
				(previous.call != nil && previous.call.signature == "Ljava/io/File;->listFiles()[Ljava/io/File;") {
				out[previous.index] = true
				continue
			}
			if previous.call != nil && modeledReceiverMutation(*previous.call) && strings.Contains(previous.call.signature, "->append(") {
				more, ok := in.objectOrigins(signature, previous.index-1, previous.call.registers[0], depth+1, visiting)
				if !ok {
					return nil, false
				}
				for origin := range more {
					out[origin] = true
				}
				continue
			}
			return nil, false
		case node.op == "check-cast":
			alias = register
		default:
			return nil, false
		}
		more, ok := in.objectOrigins(signature, id-1, alias, depth+1, visiting)
		if !ok {
			return nil, false
		}
		for origin := range more {
			out[origin] = true
		}
	}
	return out, true
}
