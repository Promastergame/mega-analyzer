package ml

import (
	"fmt"
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/cfg"
)

var (
	spLabelRe  = regexp.MustCompile(`^:([A-Za-z0-9_.$-]+)$`)
	spBranchRe = regexp.MustCompile(`\b(?:if-[^\s]+|goto(?:/\d+)?).*(:[A-Za-z0-9_.$-]+)\s*$`)
	spRegRe    = regexp.MustCompile(`\b(v\d+|p\d+)\b`)
)

type methodStructure struct {
	labels       map[string]bool
	branchTarget map[string]bool
	branches     int
	tryRegions   int
	catchClauses int
}

// preflightBodyStructure checks invariants for body-preserving strategies.
// It intentionally does not demand identical instruction counts: a surgical
// replacement may change textual instruction width, while labels, branch
// targets, and exception regions must remain coherent.
func preflightBodyStructure(original, patched string) ValidationResult {
	o := inspectMethodStructure(original)
	p := inspectMethodStructure(patched)
	result := ValidationResult{Valid: true}
	if len(o.labels) != len(p.labels) {
		result.addStructuralError("label set changed")
	}
	for label := range o.labels {
		if !p.labels[label] {
			result.addStructuralError("label removed: " + label)
		}
	}
	for target := range p.branchTarget {
		if !p.labels[target] {
			result.addStructuralError("branch target missing: " + target)
		}
	}
	if o.tryRegions != p.tryRegions || o.catchClauses != p.catchClauses {
		result.addStructuralError("try/catch regions changed")
	}
	if o.branches != p.branches {
		result.Warnings = append(result.Warnings, fmt.Sprintf("branch count changed from %d to %d", o.branches, p.branches))
	}
	result.merge(cfgStructuralDiff(original, patched))
	result.merge(dfgSemanticDiff(original, patched))
	result.merge(useDefPreflight(patched))
	result.merge(useDefPathsPreflight(patched))
	return result
}

// dfgSemanticDiff compares the role of values feeding returns and branch
// predicates. Constant contents are intentionally ignored because changing a
// constant is the purpose of several surgical strategies; changing a return
// from an invoke/field-derived value to an unrelated source is not.
func dfgSemanticDiff(original, patched string) ValidationResult {
	result := ValidationResult{Valid: true}
	oldRoles := dfgValueRoles(original)
	newRoles := dfgValueRoles(patched)
	if len(oldRoles) == 0 || len(newRoles) == 0 {
		return result
	}
	if len(oldRoles) != len(newRoles) {
		result.addStructuralError("DFG return/branch role count changed")
		return result
	}
	for i := range oldRoles {
		if oldRoles[i] != newRoles[i] {
			// Return-value override strategies intentionally insert a typed const
			// immediately before return. That changes the final def, but not the
			// control/data-flow shape being patched. Branch predicates remain strict.
			if strings.HasPrefix(oldRoles[i], "return:") && strings.HasPrefix(newRoles[i], "return:const") {
				continue
			}
			result.addStructuralError(fmt.Sprintf("DFG value role changed at site %d: %s -> %s", i, oldRoles[i], newRoles[i]))
		}
	}
	return result
}

func dfgValueRoles(code string) []string {
	graph := buildPreflightCFG(code)
	if graph == nil || graph.Method == nil {
		return nil
	}
	analysis := cfg.NewDFGAnalyzer(graph)
	analysis.Analyze()
	roles := make([]string, 0)
	lastRole := make(map[string]string)
	for _, instruction := range graph.Method.Instructions {
		if instruction == nil {
			continue
		}
		opcode := instruction.Opcode
		role := ""
		switch {
		case strings.HasPrefix(opcode, "const"):
			role = "const"
		case strings.HasPrefix(opcode, "invoke"):
			role = "invoke"
		case strings.HasPrefix(opcode, "iget"), strings.HasPrefix(opcode, "sget"):
			role = "field"
		case strings.HasPrefix(opcode, "move") && len(instruction.MoveSrc) > 0:
			role = "move"
		}
		for _, defined := range instruction.DefRegs {
			if role != "" {
				lastRole[defined] = role
			}
		}
		if strings.HasPrefix(opcode, "move-result") && instruction.InvokeRef != "" {
			for _, defined := range instruction.DefRegs {
				lastRole[defined] = "invoke"
			}
		}
		if strings.HasPrefix(opcode, "return") && opcode != "return-void" {
			for _, used := range instruction.UseRegs {
				roles = append(roles, "return:"+lastRole[used])
			}
		}
		if strings.HasPrefix(opcode, "if-") {
			for _, used := range instruction.UseRegs {
				roles = append(roles, "branch:"+lastRole[used])
			}
		}
	}
	return roles
}

// previousExecutableLine returns the nearest preceding line that can execute:
// blank lines, #-comments and debug metadata are transparent to an
// invoke/move-result pair (baksmali emits both between them), while labels
// and any other directive stop the walk — a branch target between the two
// genuinely orphans the move-result.
func previousExecutableLine(lines []string, idx int) string {
	for j := idx - 1; j >= 0; j-- {
		t := strings.TrimSpace(lines[j])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, ".") {
			name := t
			if k := strings.IndexByte(name, ' '); k >= 0 {
				name = name[:k]
			}
			// Only debug metadata is transparent; anything else (labels,
			// try/catch directives, payload data, method boundaries) ends
			// the pair the same way a real instruction does.
			switch name {
			case ".line", ".local", ".param", ".prologue", ".epilogue",
				".source", ".registers", ".locals", ".annotation":
				continue
			}
			if strings.HasPrefix(t, ".end annotation") {
				continue
			}
			return t
		}
		if strings.HasPrefix(t, ":") {
			return t
		}
		return t
	}
	return ""
}

// useDefPreflight covers verifier failures that are orthogonal to CFG shape:
// orphaned move-result instructions and registers that are never defined at
// all. It intentionally does not attempt path-sensitive liveness, because a
// register defined on one branch can be valid at a merge point.
func useDefPreflight(code string) ValidationResult {
	result := ValidationResult{Valid: true}
	lines := strings.Split(canonicalPatchText(code), "\n")
	defined := make(map[string]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".method ") {
			for _, reg := range spRegRe.FindAllString(trimmed, -1) {
				if strings.HasPrefix(reg, "p") {
					defined[reg] = true
				}
			}
		}
	}
	markRegistersStyleParameterAliases(defined, lines)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, ":") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		opcode := fields[0]
		if strings.HasPrefix(opcode, "move-result") {
			if prev := previousExecutableLine(lines, i); prev == "" || !strings.HasPrefix(prev, "invoke-") {
				result.addStructuralError(fmt.Sprintf("orphan %s at line %d", opcode, i+1))
			}
		}
		regs := spRegRe.FindAllString(trimmed, -1)
		if len(regs) == 0 {
			continue
		}
		if isUseDefDestination(opcode) {
			defined[regs[0]] = true
		}
	}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, ":") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "move-result") {
			continue
		}
		regs := spRegRe.FindAllString(trimmed, -1)
		start := 0
		if isUseDefDestination(fields[0]) && len(regs) > 0 {
			start = 1
		}
		for _, reg := range regs[start:] {
			if strings.HasPrefix(reg, "v") && !defined[reg] {
				result.addStructuralError(fmt.Sprintf("register %s is never defined at line %d", reg, i+1))
			}
		}
	}
	return result
}

// useDefPathsPreflight — path-sensitive дополнение к useDefPreflight (P2#8):
// reaching-definitions по настоящему CFG. Использование v-регистра, до
// которого не доходит ни одно определение ни на одном входящем пути,
// фиксируется предупреждением. Только warnings: параметры в
// .registers-стиле и внешние факты покрыты строгой проверкой выше, а здесь
// важно выявление, а не блокировка.
func useDefPathsPreflight(code string) ValidationResult {
	result := ValidationResult{Valid: true}
	graph := buildPreflightCFG(code)
	if graph == nil || graph.Method == nil || len(graph.Nodes) == 0 {
		return result
	}
	insns := graph.Method.Instructions
	if len(insns) == 0 {
		return result
	}
	// Def/Use-регистры заполняются только проходом DFG-анализа.
	cfg.NewDFGAnalyzer(graph).Analyze()

	lines := strings.Split(canonicalPatchText(code), "\n")
	entry := map[string]bool{}
	markRegistersStyleParameterAliases(entry, lines)

	nodeIdx := make(map[*cfg.CFGNode]int, len(graph.Nodes))
	for i, n := range graph.Nodes {
		if n != nil {
			nodeIdx[n] = i
		}
	}

	defsOf := func(n *cfg.CFGNode) map[string]bool {
		defs := map[string]bool{}
		if n == nil {
			return defs
		}
		for k := n.StartIdx; k <= n.EndIdx && k < len(insns); k++ {
			if k < 0 || insns[k] == nil {
				continue
			}
			for _, d := range insns[k].DefRegs {
				if strings.HasPrefix(d, "v") {
					defs[d] = true
				}
			}
		}
		return defs
	}

	// Available definitions (MUST-анализ по именам регистров): регистр
	// доступен в точке, только если определён на ВСЕХ входящих путях.
	// IN[b] = ∩ OUT[preds]; OUT[b] = IN[b] ∪ GEN[b]. Убывающая цепочка —
	// инициализация универсумом, сходится за пару итераций.
	allRegs := map[string]bool{}
	for _, ins := range insns {
		if ins == nil {
			continue
		}
		for _, r := range append(append([]string{}, ins.DefRegs...), ins.UseRegs...) {
			if strings.HasPrefix(r, "v") {
				allRegs[r] = true
			}
		}
	}
	in := make([]map[string]bool, len(graph.Nodes))
	out := make([]map[string]bool, len(graph.Nodes))
	for i, n := range graph.Nodes {
		if n == nil {
			continue
		}
		in[i] = map[string]bool{}
		out[i] = map[string]bool{}
		if len(n.Predecessors) == 0 {
			for reg := range entry {
				in[i][reg] = true
			}
		} else {
			for reg := range allRegs {
				out[i][reg] = true
			}
		}
		for reg := range defsOf(n) {
			out[i][reg] = true
		}
	}

	for changed := true; changed; {
		changed = false
		for i, n := range graph.Nodes {
			if n == nil {
				continue
			}
			if len(n.Predecessors) > 0 {
				first := true
				next := map[string]bool{}
				for _, pred := range n.Predecessors {
					pi, ok := nodeIdx[pred]
					if !ok {
						continue
					}
					if first {
						for reg := range out[pi] {
							next[reg] = true
						}
						first = false
					} else {
						for reg := range next {
							if !out[pi][reg] {
								delete(next, reg)
							}
						}
					}
				}
				if !first && !equalRegSets(in[i], next) {
					in[i] = next
					changed = true
				}
			}
			want := make(map[string]bool, len(in[i])+2)
			for reg := range in[i] {
				want[reg] = true
			}
			for reg := range defsOf(n) {
				want[reg] = true
			}
			if !equalRegSets(out[i], want) {
				out[i] = want
				changed = true
			}
		}
	}

	return useDefPathsCheckUses(graph.Nodes, nodeIdx, insns, in, result)
}

func equalRegSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for reg := range a {
		if !b[reg] {
			return false
		}
	}
	return true
}

func useDefPathsCheckUses(graphNodes []*cfg.CFGNode, nodeIdx map[*cfg.CFGNode]int, insns []*cfg.Instruction, in []map[string]bool, result ValidationResult) ValidationResult {
	reported := map[string]bool{}
	for i, n := range graphNodes {
		if n == nil {
			continue
		}
		local := map[string]bool{}
		for k := n.StartIdx; k <= n.EndIdx && k < len(insns); k++ {
			if k < 0 || insns[k] == nil {
				continue
			}
			for _, u := range insns[k].UseRegs {
				if !strings.HasPrefix(u, "v") || local[u] || in[i][u] {
					continue
				}
				key := fmt.Sprintf("%s@%d", u, insns[k].Line)
				if !reported[key] {
					reported[key] = true
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("register %s possibly undefined on some path (line %d)", u, insns[k].Line))
				}
			}
			for _, d := range insns[k].DefRegs {
				if strings.HasPrefix(d, "v") {
					local[d] = true
				}
			}
		}
	}
	return result
}

// markRegistersStyleParameterAliases maps `.registers N` bodies to their
// implicit parameter registers. Baksmali emits this style: with paramRegs
// parameter slots, p0..pN-1 live in v(N-paramRegs)..v(N-1), so a legitimate
// `iget-object v0, v3` (this.field) must not be flagged as undefined.
func markRegistersStyleParameterAliases(defined map[string]bool, lines []string) {
	header := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".method ") {
			header = trimmed
			break
		}
	}
	if header == "" {
		return
	}
	isStatic := strings.Contains(" "+strings.ToLower(header)+" ", " static ")
	sig := ""
	if m := lintDescRe.FindStringSubmatch(header); len(m) > 1 {
		sig = m[1]
	}
	paramRegs := countParamRegisters(sig, isStatic)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := svRegistersRe.FindStringSubmatch(trimmed); len(m) > 1 {
			total := atoiSafe(m[1])
			base := total - paramRegs
			if base < 0 {
				base = 0
			}
			for i := base; i < total; i++ {
				defined[fmt.Sprintf("v%d", i)] = true
			}
			return
		}
		// `.locals K` style addresses parameters as p-registers directly.
		if svLocalsRe.MatchString(trimmed) {
			return
		}
	}
}

func isUseDefDestination(opcode string) bool {
	if strings.HasPrefix(opcode, "invoke-") || strings.HasPrefix(opcode, "if-") || strings.HasPrefix(opcode, "return") || opcode == "throw" || strings.HasPrefix(opcode, "goto") {
		return false
	}
	for _, prefix := range []string{"move", "const", "iget", "iput", "sget", "sput", "aget", "aput", "new-", "array-length", "instance-of", "check-cast", "cmp", "add-", "sub-", "mul-", "div-", "rem-", "neg-", "not-", "shl-", "shr-", "ushr-", "and-", "or-", "xor-"} {
		if strings.HasPrefix(opcode, prefix) {
			return strings.HasPrefix(opcode, "move") || strings.HasPrefix(opcode, "const") || strings.HasPrefix(opcode, "iget") || strings.HasPrefix(opcode, "sget") || strings.HasPrefix(opcode, "aget") || strings.HasPrefix(opcode, "new-") || strings.HasPrefix(opcode, "array-length") || strings.HasPrefix(opcode, "instance-of") || strings.HasPrefix(opcode, "check-cast") || strings.HasPrefix(opcode, "cmp") || strings.Contains(opcode, "-")
		}
	}
	return false
}

// cfgStructuralDiff compares the real basic-block graph in addition to the
// textual invariants above. It is deliberately conservative: a changed edge,
// node kind, or reachability result blocks a surgical artifact rather than
// guessing that the edit is harmless.
func cfgStructuralDiff(original, patched string) ValidationResult {
	result := ValidationResult{Valid: true}
	oldGraph := buildPreflightCFG(original)
	newGraph := buildPreflightCFG(patched)
	if oldGraph == nil || newGraph == nil {
		result.Warnings = append(result.Warnings, "CFG unavailable for structural comparison")
		return result
	}
	if len(oldGraph.Nodes) != len(newGraph.Nodes) {
		result.addStructuralError("basic-block count changed")
	}
	if len(oldGraph.Edges) != len(newGraph.Edges) {
		result.addStructuralError("CFG edge count changed")
	}
	oldEdges := cfgEdgeShape(oldGraph)
	newEdges := cfgEdgeShape(newGraph)
	for edge := range oldEdges {
		if !newEdges[edge] {
			result.addStructuralError("CFG edge removed: " + edge)
		}
	}
	for edge := range newEdges {
		if !oldEdges[edge] {
			result.addStructuralError("CFG edge added: " + edge)
		}
	}
	oldUnreachable := cfgUnreachable(oldGraph)
	newUnreachable := cfgUnreachable(newGraph)
	if oldUnreachable != newUnreachable {
		result.addStructuralError("CFG reachability changed")
	}
	return result
}

func buildPreflightCFG(code string) *cfg.ControlFlowGraph {
	lines := strings.Split(canonicalPatchText(code), "\n")
	if len(lines) == 0 {
		return nil
	}
	result := cfg.NewCFGBuilder().BuildEx(cfg.BuildInputFromLines("", "preflight", "", lines))
	if result == nil {
		return nil
	}
	return result.CFG
}

func cfgEdgeShape(graph *cfg.ControlFlowGraph) map[string]bool {
	shapes := make(map[string]bool, len(graph.Edges))
	for _, edge := range graph.Edges {
		if edge == nil || edge.From == nil || edge.To == nil {
			continue
		}
		shapes[fmt.Sprintf("%d>%d:%s", edge.From.ID, edge.To.ID, edge.Type.String())] = true
	}
	return shapes
}

func cfgUnreachable(graph *cfg.ControlFlowGraph) int {
	count := 0
	for _, node := range graph.Nodes {
		if node != nil && !node.Reachable {
			count++
		}
	}
	return count
}

func (r *ValidationResult) merge(other ValidationResult) {
	r.Warnings = append(r.Warnings, other.Warnings...)
	if !other.Valid {
		r.Valid = false
		r.Errors = append(r.Errors, other.Errors...)
	}
}

func (r *ValidationResult) addStructuralError(message string) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationError{Message: message, Code: ErrControlFlowIssue})
}

func inspectMethodStructure(code string) methodStructure {
	result := methodStructure{labels: make(map[string]bool), branchTarget: make(map[string]bool)}
	for _, line := range strings.Split(canonicalPatchText(code), "\n") {
		trimmed := strings.TrimSpace(line)
		if spLabelRe.MatchString(trimmed) {
			result.labels[trimmed] = true
		}
		if spBranchRe.MatchString(trimmed) {
			result.branches++
			match := spBranchRe.FindStringSubmatch(trimmed)
			if len(match) == 2 {
				result.branchTarget[match[1]] = true
			}
		}
		if strings.HasPrefix(trimmed, ".catch ") || strings.HasPrefix(trimmed, ".catchall") {
			result.catchClauses++
		}
		if strings.HasPrefix(trimmed, ":try_start") {
			result.tryRegions++
		}
	}
	return result
}

func requiresStructurePreservation(patchType PatchType) bool {
	switch patchType {
	case PatchNop, PatchConstReplace, PatchReturnZero, PatchReturnMaxInt:
		return true
	default:
		return false
	}
}
