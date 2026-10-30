// Package analyzer — callgraph.go v5.0
// Call graph builder + analyzer with:
//   - Thread-safe concurrent construction
//   - Deep-copy immutable snapshots
//   - Graph analysis: entry/leaf detection, critical methods, protection flows
//   - BFS path finding with depth limits
//   - Fan-in/fan-out metrics and bottleneck scoring
//   - Subgraph extraction by keyword filter
//   - Protection flow detection (check → enforce chains)
package analyzer

import (
	"sort"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CALL GRAPH BUILDER — thread-safe construction
// ═══════════════════════════════════════════════════════════════════════════════

// CallGraphBuilder строит граф вызовов методов.
// Thread-safe для конкурентного добавления методов.
type CallGraphBuilder struct {
	mu    sync.RWMutex
	graph *types.CallGraph

	// Дедупликация связей
	callsSet    map[string]map[string]struct{}
	calledBySet map[string]map[string]struct{}
}

// NewCallGraphBuilder создаёт новый builder.
func NewCallGraphBuilder() *CallGraphBuilder {
	return &CallGraphBuilder{
		graph: &types.CallGraph{
			Nodes: make(map[string]*types.MethodNode, 512),
		},
		callsSet:    make(map[string]map[string]struct{}, 512),
		calledBySet: make(map[string]map[string]struct{}, 512),
	}
}

// AddMethod добавляет метод и его вызовы в граф. Thread-safe.
func (b *CallGraphBuilder) AddMethod(className string, method *types.SmaliMethod, filePath string) {
	fullName := formatMethodFullName(className, method.Name, method.Params, method.ReturnType)

	b.mu.Lock()
	defer b.mu.Unlock()

	node := b.getOrCreateNodeLocked(fullName, className, method.Name, filePath, method.LineStart)

	if b.callsSet[fullName] == nil {
		b.callsSet[fullName] = make(map[string]struct{}, len(method.Invokes))
	}

	for _, invoke := range method.Invokes {
		calledFullName := formatInvokeFullName(invoke)

		if _, exists := b.callsSet[fullName][calledFullName]; exists {
			continue
		}
		b.callsSet[fullName][calledFullName] = struct{}{}
		node.Calls = append(node.Calls, calledFullName)

		calledNode := b.getOrCreateNodeLocked(calledFullName, invoke.Class, invoke.Method, "", 0)

		if b.calledBySet[calledFullName] == nil {
			b.calledBySet[calledFullName] = make(map[string]struct{}, 4)
		}
		if _, exists := b.calledBySet[calledFullName][fullName]; !exists {
			b.calledBySet[calledFullName][fullName] = struct{}{}
			calledNode.CalledBy = append(calledNode.CalledBy, fullName)
		}
	}
}

func (b *CallGraphBuilder) getOrCreateNodeLocked(
	fullName, className, methodName, filePath string, line int,
) *types.MethodNode {
	if node, exists := b.graph.Nodes[fullName]; exists {
		if node.File == "" && filePath != "" {
			node.File = filePath
			node.Line = line
		}
		return node
	}

	node := &types.MethodNode{
		SourceLocation: types.SourceLocation{File: filePath, Line: line},
		FullName:       fullName,
		Class:          className,
		Method:         methodName,
		Calls:          make([]string, 0, 8),
		CalledBy:       make([]string, 0, 4),
	}
	b.graph.Nodes[fullName] = node
	return node
}

// Build возвращает immutable deep-copy snapshot.
func (b *CallGraphBuilder) Build() *types.CallGraph {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := &types.CallGraph{
		Nodes: make(map[string]*types.MethodNode, len(b.graph.Nodes)),
	}

	for name, node := range b.graph.Nodes {
		nodeCopy := &types.MethodNode{
			SourceLocation: node.SourceLocation,
			FullName:       node.FullName,
			Class:          node.Class,
			Method:         node.Method,
		}
		if len(node.Calls) > 0 {
			nodeCopy.Calls = make([]string, len(node.Calls))
			copy(nodeCopy.Calls, node.Calls)
		}
		if len(node.CalledBy) > 0 {
			nodeCopy.CalledBy = make([]string, len(node.CalledBy))
			copy(nodeCopy.CalledBy, node.CalledBy)
		}
		result.Nodes[name] = nodeCopy
	}

	return result
}

// NodeCount возвращает количество узлов.
func (b *CallGraphBuilder) NodeCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.graph.Nodes)
}

// ═══════════════════════════════════════════════════════════════════════════════
// NAME FORMATTING — optimized with strings.Builder
// ═══════════════════════════════════════════════════════════════════════════════

// normalizeClassDescriptor converts any class name spelling to the dex
// descriptor form `Lcom/x/Foo;` (audit D1). Parser-produced invoke targets
// arrive in dot form (`com.x.Foo`), declared methods as dotted or slashed
// names, and synthetic fixtures sometimes already with an L prefix. Without
// one canonical form, callee nodes created from invokes never join the
// caller nodes of the same real method and the graph splits into orphan
// name variants — breaking every downstream path/reachability analysis.
func normalizeClassDescriptor(className string) string {
	name := className
	// Only strip a genuine descriptor wrapper (`L…;` or slashed `L…`) — a
	// bare leading 'L' without separators (e.g. class "License") must
	// survive.
	if len(name) > 2 && name[0] == 'L' && (strings.HasSuffix(name, ";") || strings.Contains(name, "/")) {
		name = strings.TrimSuffix(name[1:], ";")
	}
	name = strings.ReplaceAll(name, ".", "/")
	return "L" + name + ";"
}

func formatMethodFullName(className, methodName, params, returnType string) string {
	classDesc := normalizeClassDescriptor(className)

	size := len(classDesc) + 3 + len(methodName) + 1 + len(params) + 1 + len(returnType)

	var sb strings.Builder
	sb.Grow(size)
	sb.WriteString(classDesc)
	sb.WriteString("->")
	sb.WriteString(methodName)
	sb.WriteByte('(')
	sb.WriteString(params)
	sb.WriteByte(')')
	sb.WriteString(returnType)

	return sb.String()
}

func formatInvokeFullName(invoke types.Invoke) string {
	classDesc := normalizeClassDescriptor(invoke.Class)

	size := len(classDesc) + 3 + len(invoke.Method) + 1 + len(invoke.Params) + 1 + len(invoke.ReturnType)

	var sb strings.Builder
	sb.Grow(size)
	sb.WriteString(classDesc)
	sb.WriteString("->")
	sb.WriteString(invoke.Method)
	sb.WriteByte('(')
	sb.WriteString(invoke.Params)
	sb.WriteByte(')')
	sb.WriteString(invoke.ReturnType)

	return sb.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// GRAPH ANALYZER — static analysis on built graph
// ═══════════════════════════════════════════════════════════════════════════════

// GraphAnalyzer выполняет анализ построенного графа вызовов.
type GraphAnalyzer struct {
	graph *types.CallGraph

	// Cached metrics
	fanIn  map[string]int // method → number of callers
	fanOut map[string]int // method → number of callees
}

// NewGraphAnalyzer создаёт анализатор для построенного графа.
func NewGraphAnalyzer(graph *types.CallGraph) *GraphAnalyzer {
	ga := &GraphAnalyzer{
		graph:  graph,
		fanIn:  make(map[string]int, len(graph.Nodes)),
		fanOut: make(map[string]int, len(graph.Nodes)),
	}
	ga.computeMetrics()
	return ga
}

func (ga *GraphAnalyzer) computeMetrics() {
	for name, node := range ga.graph.Nodes {
		ga.fanOut[name] = len(node.Calls)
		ga.fanIn[name] = len(node.CalledBy)
	}
}

// ── Graph Statistics ─────────────────────────────────────────────────────

// GraphStats содержит общую статистику графа.
type GraphStats struct {
	TotalNodes    int
	TotalEdges    int
	EntryPoints   int // nodes with fanIn=0, fanOut>0
	LeafNodes     int // nodes with fanOut=0, fanIn>0
	Isolates      int // nodes with fanIn=0, fanOut=0
	MaxFanIn      int
	MaxFanOut     int
	AvgFanIn      float64
	AvgFanOut     float64
	UniqueClasses int
}

// Stats вычисляет общую статистику графа.
func (ga *GraphAnalyzer) Stats() GraphStats {
	stats := GraphStats{
		TotalNodes: len(ga.graph.Nodes),
	}

	if stats.TotalNodes == 0 {
		return stats
	}

	classSet := make(map[string]struct{}, stats.TotalNodes/3)
	totalFanIn, totalFanOut := 0, 0

	for name, node := range ga.graph.Nodes {
		fi := ga.fanIn[name]
		fo := ga.fanOut[name]

		stats.TotalEdges += fo
		totalFanIn += fi
		totalFanOut += fo

		if fi > stats.MaxFanIn {
			stats.MaxFanIn = fi
		}
		if fo > stats.MaxFanOut {
			stats.MaxFanOut = fo
		}

		switch {
		case fi == 0 && fo == 0:
			stats.Isolates++
		case fi == 0 && fo > 0:
			stats.EntryPoints++
		case fo == 0 && fi > 0:
			stats.LeafNodes++
		}

		classSet[node.Class] = struct{}{}
	}

	n := float64(stats.TotalNodes)
	stats.AvgFanIn = float64(totalFanIn) / n
	stats.AvgFanOut = float64(totalFanOut) / n
	stats.UniqueClasses = len(classSet)

	return stats
}

// ── Entry & Leaf Points ──────────────────────────────────────────────────

// EntryPoints возвращает методы без вызывающих (fanIn=0, fanOut>0).
// Это потенциальные точки входа в код приложения.
func (ga *GraphAnalyzer) EntryPoints() []*types.MethodNode {
	result := make([]*types.MethodNode, 0, 32)
	for name, node := range ga.graph.Nodes {
		if ga.fanIn[name] == 0 && ga.fanOut[name] > 0 {
			result = append(result, node)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].FullName < result[j].FullName
	})
	return result
}

// LeafNodes возвращает методы без исходящих вызовов (внешние API).
func (ga *GraphAnalyzer) LeafNodes() []*types.MethodNode {
	result := make([]*types.MethodNode, 0, 64)
	for name, node := range ga.graph.Nodes {
		if ga.fanOut[name] == 0 && ga.fanIn[name] > 0 {
			result = append(result, node)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].FullName < result[j].FullName
	})
	return result
}

// ── Critical Methods ─────────────────────────────────────────────────────

// CriticalMethod описывает метод с высоким влиянием на граф.
type CriticalMethod struct {
	Node             *types.MethodNode
	FanIn            int
	FanOut           int
	BetweennessProxy float64 // fanIn × fanOut — proxy для betweenness centrality
	Score            float64
	IsSuspiciousName bool
}

// FindCriticalMethods находит методы с высоким fan-in × fan-out
// (потенциальные bottleneck'и и orchestrator'ы).
func (ga *GraphAnalyzer) FindCriticalMethods(topN int) []CriticalMethod {
	if len(ga.graph.Nodes) == 0 || topN <= 0 {
		return nil
	}

	result := make([]CriticalMethod, 0, len(ga.graph.Nodes)/4)

	for name, node := range ga.graph.Nodes {
		fi := ga.fanIn[name]
		fo := ga.fanOut[name]

		// Минимальный порог: хотя бы 2 caller и 2 callee
		if fi < 2 || fo < 2 {
			continue
		}

		betweenness := float64(fi) * float64(fo)
		methodName := extractMethodName(name)
		suspicious := isMethodNameSuspicious(methodName)

		score := betweenness
		if suspicious {
			score *= 2.0 // boost for suspicious names
		}

		result = append(result, CriticalMethod{
			Node:             node,
			FanIn:            fi,
			FanOut:           fo,
			BetweennessProxy: betweenness,
			Score:            score,
			IsSuspiciousName: suspicious,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Score > result[j].Score
	})

	if len(result) > topN {
		result = result[:topN]
	}

	return result
}

// ── Most Connected ───────────────────────────────────────────────────────

// MostCalled возвращает N методов с наибольшим fan-in.
func (ga *GraphAnalyzer) MostCalled(topN int) []*types.MethodNode {
	type entry struct {
		node  *types.MethodNode
		fanIn int
	}

	entries := make([]entry, 0, len(ga.graph.Nodes)/4)
	for name, node := range ga.graph.Nodes {
		fi := ga.fanIn[name]
		if fi > 0 {
			entries = append(entries, entry{node, fi})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].fanIn > entries[j].fanIn
	})

	if len(entries) > topN {
		entries = entries[:topN]
	}

	result := make([]*types.MethodNode, len(entries))
	for i, e := range entries {
		result[i] = e.node
	}
	return result
}

// MostCalling возвращает N методов с наибольшим fan-out.
func (ga *GraphAnalyzer) MostCalling(topN int) []*types.MethodNode {
	type entry struct {
		node   *types.MethodNode
		fanOut int
	}

	entries := make([]entry, 0, len(ga.graph.Nodes)/4)
	for name, node := range ga.graph.Nodes {
		fo := ga.fanOut[name]
		if fo > 0 {
			entries = append(entries, entry{node, fo})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].fanOut > entries[j].fanOut
	})

	if len(entries) > topN {
		entries = entries[:topN]
	}

	result := make([]*types.MethodNode, len(entries))
	for i, e := range entries {
		result[i] = e.node
	}
	return result
}

// ── BFS Path Finding ─────────────────────────────────────────────────────

// FindPath ищет кратчайший путь между двумя методами (BFS).
// maxDepth ограничивает глубину поиска. 0 = без ограничения.
// Возвращает nil если путь не найден.
func (ga *GraphAnalyzer) FindPath(from, to string, maxDepth int) []string {
	if from == to {
		return []string{from}
	}

	if _, ok := ga.graph.Nodes[from]; !ok {
		return nil
	}
	if _, ok := ga.graph.Nodes[to]; !ok {
		return nil
	}

	if maxDepth <= 0 {
		maxDepth = 20
	}

	type bfsEntry struct {
		name  string
		depth int
	}

	visited := make(map[string]string, 64) // node → predecessor
	visited[from] = ""

	queue := make([]bfsEntry, 0, 64)
	queue = append(queue, bfsEntry{from, 0})

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= maxDepth {
			continue
		}

		node, ok := ga.graph.Nodes[current.name]
		if !ok {
			continue
		}

		for _, callee := range node.Calls {
			if _, seen := visited[callee]; seen {
				continue
			}
			visited[callee] = current.name

			if callee == to {
				// Reconstruct path
				return reconstructPath(visited, from, to)
			}

			queue = append(queue, bfsEntry{callee, current.depth + 1})
		}
	}

	return nil
}

func reconstructPath(predecessors map[string]string, from, to string) []string {
	path := []string{to}
	current := to

	for current != from {
		prev, ok := predecessors[current]
		if !ok {
			return nil // broken chain
		}
		path = append(path, prev)
		current = prev

		if len(path) > 100 {
			return nil // safety limit
		}
	}

	// Reverse
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}

	return path
}

// ── Reachability ─────────────────────────────────────────────────────────

// Reachable возвращает все методы достижимые из startNode (BFS).
func (ga *GraphAnalyzer) Reachable(startNode string, maxDepth int) map[string]int {
	if _, ok := ga.graph.Nodes[startNode]; !ok {
		return nil
	}

	if maxDepth <= 0 {
		maxDepth = 30
	}

	type bfsEntry struct {
		name  string
		depth int
	}

	result := make(map[string]int, 32) // method → distance
	result[startNode] = 0

	queue := []bfsEntry{{startNode, 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= maxDepth {
			continue
		}

		node, ok := ga.graph.Nodes[current.name]
		if !ok {
			continue
		}

		for _, callee := range node.Calls {
			if _, seen := result[callee]; seen {
				continue
			}
			dist := current.depth + 1
			result[callee] = dist
			queue = append(queue, bfsEntry{callee, dist})
		}
	}

	return result
}

// ── Callers (reverse reachability) ───────────────────────────────────────

// Callers возвращает все методы, которые прямо или косвенно вызывают target.
func (ga *GraphAnalyzer) Callers(target string, maxDepth int) map[string]int {
	if _, ok := ga.graph.Nodes[target]; !ok {
		return nil
	}

	if maxDepth <= 0 {
		maxDepth = 20
	}

	type bfsEntry struct {
		name  string
		depth int
	}

	result := make(map[string]int, 16)
	result[target] = 0

	queue := []bfsEntry{{target, 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= maxDepth {
			continue
		}

		node, ok := ga.graph.Nodes[current.name]
		if !ok {
			continue
		}

		for _, caller := range node.CalledBy {
			if _, seen := result[caller]; seen {
				continue
			}
			dist := current.depth + 1
			result[caller] = dist
			queue = append(queue, bfsEntry{caller, dist})
		}
	}

	return result
}

// ── Protection Flow Detection ────────────────────────────────────────────

// ProtectionFlow описывает цепочку: caller → check → enforce.
type ProtectionFlow struct {
	Orchestrator   string   // метод, который координирует
	CheckMethods   []string // вызываемые check-методы
	EnforceMethods []string // вызываемые enforce-методы
	Score          float64
}

// FindProtectionFlows находит методы, которые вызывают И check И enforce.
// Это паттерн: if (!isLicensed()) { finish(); }
func (ga *GraphAnalyzer) FindProtectionFlows() []ProtectionFlow {
	var flows []ProtectionFlow

	for name, node := range ga.graph.Nodes {
		if len(node.Calls) < 2 {
			continue
		}

		var checks, enforces []string

		for _, callee := range node.Calls {
			calleeMethod := extractMethodName(callee)
			if calleeMethod == "" {
				continue
			}

			methodLower := strings.ToLower(calleeMethod)

			if isCheckMethod(methodLower) {
				checks = append(checks, callee)
			}
			if isEnforceMethod(methodLower) {
				enforces = append(enforces, callee)
			}
		}

		if len(checks) > 0 && len(enforces) > 0 {
			score := float64(len(checks)+len(enforces)) * 10.0

			// Boost if orchestrator has suspicious name
			if isMethodNameSuspicious(extractMethodName(name)) {
				score *= 1.5
			}

			flows = append(flows, ProtectionFlow{
				Orchestrator:   name,
				CheckMethods:   checks,
				EnforceMethods: enforces,
				Score:          score,
			})
		}
	}

	sort.Slice(flows, func(i, j int) bool {
		return flows[i].Score > flows[j].Score
	})

	return flows
}

// ── Methods By Class ─────────────────────────────────────────────────────

// MethodsByClass группирует методы по классу.
func (ga *GraphAnalyzer) MethodsByClass() map[string][]*types.MethodNode {
	result := make(map[string][]*types.MethodNode, len(ga.graph.Nodes)/5)
	for _, node := range ga.graph.Nodes {
		result[node.Class] = append(result[node.Class], node)
	}
	return result
}

// ── Subgraph Extraction ──────────────────────────────────────────────────

// FilterByKeywords возвращает подмножество узлов, чьи имена содержат любой из keywords.
func (ga *GraphAnalyzer) FilterByKeywords(keywords []string) []*types.MethodNode {
	if len(keywords) == 0 {
		return nil
	}

	var result []*types.MethodNode

	for _, node := range ga.graph.Nodes {
		fullLower := strings.ToLower(node.FullName)
		for _, kw := range keywords {
			if strings.Contains(fullLower, strings.ToLower(kw)) {
				result = append(result, node)
				break
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].FullName < result[j].FullName
	})

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// extractMethodName extracts short method name from full qualified name.
// "Lcom/example/Foo;->isLicensed(...)Z" → "isLicensed"
func extractMethodName(fullName string) string {
	arrowIdx := strings.Index(fullName, ";->")
	if arrowIdx < 0 {
		return ""
	}
	rest := fullName[arrowIdx+3:]
	parenIdx := strings.IndexByte(rest, '(')
	if parenIdx < 0 {
		return rest
	}
	return rest[:parenIdx]
}

// checkMethodKeywords — ключевые слова для check-методов (lowercase).
var checkMethodKeywords = []string{
	"islicensed", "ispremium", "ispro", "ispaid", "isunlocked",
	"isfullversion", "issubscribed", "istrial", "istrialexpired",
	"isadfree", "hasnoads", "ispurchased", "haspurchased",
	"isrooted", "isemulator", "isdebuggable", "istampered",
	"ismodified", "ispirated", "iscracked", "isrepacked",
	"checklicense", "verifylicense", "validatelicense",
	"checkpurchase", "verifypurchase", "checksignature",
	"verifysignature", "checkintegrity", "verifyintegrity",
	"shouldshowads", "canshowads", "isexpired",
}

func isCheckMethod(methodLower string) bool {
	for _, kw := range checkMethodKeywords {
		if strings.Contains(methodLower, kw) {
			return true
		}
	}
	// Generic: starts with is/has/check/verify and returns boolean hint
	for _, prefix := range []string{"is", "has", "check", "verify", "validate"} {
		if strings.HasPrefix(methodLower, prefix) && len(methodLower) > len(prefix)+2 {
			return true
		}
	}
	return false
}

var enforceMethodKeywords = []string{
	"finish", "exit", "kill", "shutdown", "destroy",
	"block", "deny", "reject", "disable", "restrict",
	"showdialog", "showalert", "showwarning", "showerror",
	"displayerror", "notifyuser",
}

func isEnforceMethod(methodLower string) bool {
	for _, kw := range enforceMethodKeywords {
		if strings.Contains(methodLower, kw) {
			return true
		}
	}
	return false
}

func isMethodNameSuspicious(methodName string) bool {
	if methodName == "" {
		return false
	}
	lower := strings.ToLower(methodName)
	for _, kw := range []string{
		"license", "premium", "pro", "billing", "purchase",
		"subscri", "trial", "verify", "check", "validate",
		"crack", "piracy", "tamper", "unlock", "activate",
		"security", "integrity", "signature",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
