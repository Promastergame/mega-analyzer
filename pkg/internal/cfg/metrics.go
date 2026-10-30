package cfg

import (
	"math"

	"mega-analyzer/pkg/internal/dexir"
	"mega-analyzer/pkg/ml/fusion"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CFG METRICS - ULTIMATE EDITION
// ═══════════════════════════════════════════════════════════════════════════════
// NEW FEATURES:
//   • Halstead complexity metrics
//   • Maintainability Index (MI)
//   • Npath complexity
//   • Essential complexity
//   • Fan-in/Fan-out analysis
//   • Structural risk assessment
//   • AI/ML readiness score
//   • Obfuscation detection score
// ═══════════════════════════════════════════════════════════════════════════════

type Metrics struct {
	cfg *ControlFlowGraph
}

func NewMetrics(cfg *ControlFlowGraph) *Metrics {
	return &Metrics{cfg: cfg}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HALSTEAD COMPLEXITY METRICS
// ═══════════════════════════════════════════════════════════════════════════════

type HalsteadMetrics struct {
	N1            int     // total operators
	N2            int     // total operands
	N1Distinct    int     // unique operators (η1)
	N2Distinct    int     // unique operands (η2)
	ProgramLength int     // N = N1 + N2
	Vocabulary    int     // η = η1 + η2
	Volume        float64 // V = N * log2(η)
	Difficulty    float64 // D = (η1/2) * (N2/η2)
	Effort        float64 // E = D * V
	TimeToProgram float64 // T = E / 18 (seconds)
	DeliveredBugs float64 // B = V / 3000
}

func (m *Metrics) HalsteadComplexity() HalsteadMetrics {
	operators := make(map[string]int)
	operands := make(map[string]int)

	for _, node := range m.cfg.Nodes {
		for _, instrRef := range node.Instructions {
			opcode := instrRef.Opcode

			// Count operator
			operators[opcode]++

			// Extract operands (registers, constants, method refs)
			operandList := m.extractOperands(instrRef)
			for _, operand := range operandList {
				operands[operand]++
			}
		}
	}

	// Calculate totals
	n1 := 0
	for _, count := range operators {
		n1 += count
	}
	n2 := 0
	for _, count := range operands {
		n2 += count
	}

	eta1 := len(operators)
	eta2 := len(operands)

	N := n1 + n2
	eta := eta1 + eta2

	var volume, difficulty, effort, timeToProgram, deliveredBugs float64

	if eta > 0 {
		volume = float64(N) * math.Log2(float64(eta))
	}

	if eta2 > 0 {
		difficulty = (float64(eta1) / 2.0) * (float64(n2) / float64(eta2))
	}

	effort = difficulty * volume
	timeToProgram = effort / 18.0   // Halstead's empirical constant
	deliveredBugs = volume / 3000.0 // empirical constant

	return HalsteadMetrics{
		N1:            n1,
		N2:            n2,
		N1Distinct:    eta1,
		N2Distinct:    eta2,
		ProgramLength: N,
		Vocabulary:    eta,
		Volume:        volume,
		Difficulty:    difficulty,
		Effort:        effort,
		TimeToProgram: timeToProgram,
		DeliveredBugs: deliveredBugs,
	}
}

// extractOperands returns the Halstead operand tokens of an instruction
// from the typed IR: registers (Dst/Srcs), immediates folded to "CONST",
// and method/field/type/string references. The raw instruction line is
// no longer tokenized.
func (m *Metrics) extractOperands(instr InstructionRef) []string {
	ir := instr.IR
	if ir == nil {
		if instr.Raw != "" {
			op, ops := parseSmaliOpcode(instr.Raw)
			ir = irFromLegacy(op, ops)
		}
		if ir == nil {
			return nil
		}
	}

	var operands []string
	if ir.Dst != dexir.NoRegister {
		operands = append(operands, registerName(ir.Dst))
	}
	for _, r := range ir.Srcs {
		if reg := registerName(r); reg != "" {
			operands = append(operands, reg)
		}
	}
	if ir.HasImm {
		operands = append(operands, "CONST")
	}
	if ir.Method != nil {
		operands = append(operands, ir.Method.String())
	}
	if ir.Field != nil {
		operands = append(operands, ir.Field.String())
	}
	if ir.Type != "" {
		operands = append(operands, ir.Type)
	}
	if ir.HasStr {
		operands = append(operands, ir.Str)
	}
	return operands
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAINTAINABILITY INDEX (MI)
// ═══════════════════════════════════════════════════════════════════════════════

type MaintainabilityIndex struct {
	MI             float64 // 0-100 (higher = more maintainable)
	Rating         string  // Excellent, Good, Fair, Poor
	HalsteadVolume float64
	CyclomaticCC   int
	LinesOfCode    int
	CommentDensity float64
}

func (m *Metrics) MaintainabilityIndex() MaintainabilityIndex {
	halstead := m.HalsteadComplexity()
	cc := m.CyclomaticComplexity()
	loc := m.getLinesOfCode()

	// Microsoft's formula:
	// MI = 171 - 5.2*ln(V) - 0.23*CC - 16.2*ln(LOC) + 50*sin(sqrt(2.4*CM))
	// где CM = comment density (0-1)

	V := halstead.Volume
	if V == 0 {
		V = 1
	}

	cm := 0.0 // comment density (not available in CFG, set to 0)

	mi := 171.0 - 5.2*math.Log(V) - 0.23*float64(cc) - 16.2*math.Log(float64(loc))
	mi += 50.0 * math.Sin(math.Sqrt(2.4*cm))

	// Normalize to 0-100
	if mi < 0 {
		mi = 0
	}
	if mi > 100 {
		mi = 100
	}

	// Rating
	rating := "Poor"
	switch {
	case mi >= 85:
		rating = "Excellent"
	case mi >= 65:
		rating = "Good"
	case mi >= 40:
		rating = "Fair"
	}

	return MaintainabilityIndex{
		MI:             mi,
		Rating:         rating,
		HalsteadVolume: V,
		CyclomaticCC:   cc,
		LinesOfCode:    loc,
		CommentDensity: cm,
	}
}

func (m *Metrics) getLinesOfCode() int {
	count := 0
	for _, node := range m.cfg.Nodes {
		count += len(node.Instructions)
	}
	if count == 0 {
		return 1 // avoid log(0)
	}
	return count
}

// ═══════════════════════════════════════════════════════════════════════════════
// NPATH COMPLEXITY
// ═══════════════════════════════════════════════════════════════════════════════

// NPath = number of acyclic execution paths (exponential!)
func (m *Metrics) NPathComplexity() int64 {
	if m.cfg == nil || m.cfg.Entry == nil {
		return 0
	}

	// Collapse loops to prevent exponential explosion
	visited := make(map[int]bool)
	inStack := make(map[int]bool)

	var dfs func(node *CFGNode) int64
	dfs = func(node *CFGNode) int64 {
		if node == nil {
			return 0
		}

		// Cycle detection
		if inStack[node.ID] {
			return 1 // loop counts as 1 path
		}

		if visited[node.ID] {
			return 0
		}

		visited[node.ID] = true
		inStack[node.ID] = true

		if node.Type.IsTerminator() {
			inStack[node.ID] = false
			return 1
		}

		var npath int64

		switch node.Type {
		case NodeTypeCondition:
			// if: npath = npath(true) + npath(false) + 1
			for _, succ := range node.Successors {
				npath += dfs(succ)
			}
			if npath == 0 {
				npath = 1
			}

		case NodeTypeSwitch:
			// switch: sum of all cases
			for _, succ := range node.Successors {
				npath += dfs(succ)
			}
			if npath == 0 {
				npath = 1
			}

		default:
			// sequential: npath = npath(next)
			for _, succ := range node.Successors {
				npath += dfs(succ)
			}
			if npath == 0 {
				npath = 1
			}
		}

		inStack[node.ID] = false

		// Cap to prevent overflow
		if npath > 1000000000 {
			npath = 1000000000
		}

		return npath
	}

	return dfs(m.cfg.Entry)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ESSENTIAL COMPLEXITY (McCabe)
// ═══════════════════════════════════════════════════════════════════════════════

// Essential complexity = number of unstructured control flows
// v(G) - v(collapsed G)
func (m *Metrics) EssentialComplexity() int {
	originalCC := m.CyclomaticComplexity()

	// Collapse all structured constructs (if-then-else, loops)
	// What remains are goto, irregular exits, etc.

	collapsedGraph := m.collapseStructuredConstructs()
	collapsedCC := m.computeCC(collapsedGraph)

	essential := originalCC - collapsedCC
	if essential < 0 {
		essential = 0
	}

	return essential
}

func (m *Metrics) collapseStructuredConstructs() map[int][]int {
	// Build adjacency list
	adj := make(map[int][]int)
	for _, edge := range m.cfg.Edges {
		adj[edge.From.ID] = append(adj[edge.From.ID], edge.To.ID)
	}

	// Collapse if-then-else and loops
	// Simplified: just return original graph
	// Real implementation needs pattern matching
	return adj
}

func (m *Metrics) computeCC(adj map[int][]int) int {
	edges := 0
	for _, neighbors := range adj {
		edges += len(neighbors)
	}
	nodes := len(adj)

	// E - N + 2P
	return edges - nodes + 2
}

// ═══════════════════════════════════════════════════════════════════════════════
// FAN-IN / FAN-OUT ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

type FanMetrics struct {
	AvgFanIn       float64
	AvgFanOut      float64
	MaxFanIn       int
	MaxFanOut      int
	FanInNodes     []*CFGNode // nodes with max fan-in
	FanOutNodes    []*CFGNode // nodes with max fan-out
	StructuralRisk float64    // high fan-in/out = risk
}

func (m *Metrics) FanAnalysis() FanMetrics {
	var totalFanIn, totalFanOut int
	maxFanIn := 0
	maxFanOut := 0

	var fanInNodes, fanOutNodes []*CFGNode

	for _, node := range m.cfg.Nodes {
		fanIn := len(node.Predecessors)
		fanOut := len(node.Successors)

		totalFanIn += fanIn
		totalFanOut += fanOut

		if fanIn > maxFanIn {
			maxFanIn = fanIn
			fanInNodes = []*CFGNode{node}
		} else if fanIn == maxFanIn && maxFanIn > 0 {
			fanInNodes = append(fanInNodes, node)
		}

		if fanOut > maxFanOut {
			maxFanOut = fanOut
			fanOutNodes = []*CFGNode{node}
		} else if fanOut == maxFanOut && maxFanOut > 0 {
			fanOutNodes = append(fanOutNodes, node)
		}
	}

	n := float64(len(m.cfg.Nodes))
	if n == 0 {
		n = 1
	}

	avgFanIn := float64(totalFanIn) / n
	avgFanOut := float64(totalFanOut) / n

	// Structural risk: high fan-in/out indicates complex dependencies
	risk := (avgFanIn + avgFanOut) / 2.0

	return FanMetrics{
		AvgFanIn:       avgFanIn,
		AvgFanOut:      avgFanOut,
		MaxFanIn:       maxFanIn,
		MaxFanOut:      maxFanOut,
		FanInNodes:     fanInNodes,
		FanOutNodes:    fanOutNodes,
		StructuralRisk: risk,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// OBFUSCATION DETECTION SCORE
// ═══════════════════════════════════════════════════════════════════════════════

type ObfuscationScore struct {
	Score                 float64 // 0-100 (100 = heavily obfuscated)
	Indicators            []string
	IrreducibleLoops      int
	ExcessiveBranching    bool
	DeadCode              int
	OpaquePredicates      int
	ControlFlowFlattening bool
}

func (m *Metrics) ObfuscationDetection() ObfuscationScore {
	score := 0.0
	var indicators []string

	// 1. Check for irreducible loops
	irreducibleCount := 0
	for _, node := range m.cfg.Nodes {
		if node.LoopType == LoopIrreducible {
			irreducibleCount++
		}
	}
	if irreducibleCount > 0 {
		score += 20.0
		indicators = append(indicators, "Irreducible loops detected")
	}

	// 2. Excessive branching (CC > 50)
	cc := m.CyclomaticComplexity()
	if cc > 50 {
		score += 15.0
		indicators = append(indicators, "Excessive cyclomatic complexity")
	}

	// 3. Dead code (unreachable nodes)
	deadCount := 0
	for _, node := range m.cfg.Nodes {
		if !node.Reachable {
			deadCount++
		}
	}
	if deadCount > len(m.cfg.Nodes)/10 {
		score += 10.0
		indicators = append(indicators, "Excessive dead code")
	}

	// 4. Opaque predicates (conditions that are always true/false)
	opaqueCount := m.detectOpaquePredicates()
	if opaqueCount > 0 {
		score += float64(opaqueCount) * 5.0
		indicators = append(indicators, "Opaque predicates detected")
	}

	// 5. Control flow flattening (dispatcher pattern)
	isFlattened := m.detectControlFlowFlattening()
	if isFlattened {
		score += 30.0
		indicators = append(indicators, "Control flow flattening detected")
	}

	// 6. High fan-in/fan-out
	fan := m.FanAnalysis()
	if fan.MaxFanIn > 20 || fan.MaxFanOut > 10 {
		score += 10.0
		indicators = append(indicators, "Abnormal fan-in/fan-out")
	}

	if score > 100 {
		score = 100
	}

	return ObfuscationScore{
		Score:                 score,
		Indicators:            indicators,
		IrreducibleLoops:      irreducibleCount,
		ExcessiveBranching:    cc > 50,
		DeadCode:              deadCount,
		OpaquePredicates:      opaqueCount,
		ControlFlowFlattening: isFlattened,
	}
}

func (m *Metrics) detectOpaquePredicates() int {
	count := 0

	for _, node := range m.cfg.Nodes {
		if node.Condition == nil {
			continue
		}

		// Check if both branches lead to same target (suspicious)
		if len(node.Successors) == 2 {
			if node.Successors[0] == node.Successors[1] {
				count++
			}
		}

		// Check for always-true conditions (const == const)
		if node.Condition.LHS != nil && node.Condition.RHS != nil {
			if node.Condition.LHS.Kind == ValueConst && node.Condition.RHS.Kind == ValueConst {
				count++
			}
		}
	}

	return count
}

func (m *Metrics) detectControlFlowFlattening() bool {
	// Dispatcher pattern: single switch with all logic in cases

	for _, node := range m.cfg.Nodes {
		if node.Type == NodeTypeSwitch {
			// Check if switch has many cases (>10) and dominates most of the graph
			if node.SwitchInfo != nil && len(node.SwitchInfo.Targets) > 10 {
				// Check if this switch is in a loop and controls most flow
				if node.LoopDepth > 0 {
					return true
				}
			}
		}
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI/ML READINESS SCORE
// ═══════════════════════════════════════════════════════════════════════════════

type AIReadinessScore struct {
	Score           float64 // 0-100
	Features        map[string]float64
	Recommendations []string
}

func (m *Metrics) AIReadiness() AIReadinessScore {
	features := make(map[string]float64)
	score := 100.0

	// Feature extraction quality
	cc := m.CyclomaticComplexity()
	if cc > 30 {
		score -= 20
		features["high_complexity"] = float64(cc)
	}

	// SSA availability
	if !m.cfg.SSAConstructed {
		score -= 15
		features["no_ssa"] = 1.0
	}

	// Loop analysis
	if !m.cfg.LoopsAnalyzed {
		score -= 10
		features["no_loop_analysis"] = 1.0
	}

	// Pattern detection
	if !m.cfg.PatternsFound {
		score -= 10
		features["no_patterns"] = 1.0
	}

	// Dominator tree
	if !m.cfg.DominatorTree {
		score -= 15
		features["no_dominators"] = 1.0
	}

	// Graph size (too small or too large)
	nodeCount := len(m.cfg.Nodes)
	if nodeCount < 5 {
		score -= 10
		features["too_small"] = 1.0
	}
	if nodeCount > 500 {
		score -= 20
		features["too_large"] = float64(nodeCount)
	}

	var recommendations []string
	if score < 80 {
		recommendations = append(recommendations, "Run full analysis pipeline (SSA, loops, patterns)")
	}
	if cc > 30 {
		recommendations = append(recommendations, "Consider splitting method into smaller functions")
	}
	if nodeCount > 500 {
		recommendations = append(recommendations, "Method too large for effective ML feature extraction")
	}

	return AIReadinessScore{
		Score:           score,
		Features:        features,
		Recommendations: recommendations,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ULTIMATE SUMMARY - ALL METRICS
// ═══════════════════════════════════════════════════════════════════════════════

type UltimateCFGMetrics struct {
	Basic               CFGMetricsSummary
	Halstead            HalsteadMetrics
	Maintainability     MaintainabilityIndex
	NPath               int64
	EssentialComplexity int
	FanAnalysis         FanMetrics
	Obfuscation         ObfuscationScore
	AIReadiness         AIReadinessScore
	FusionIntelligence  *fusion.Report `json:"fusion_intelligence,omitempty"`
}

func (m *Metrics) UltimateSummary() UltimateCFGMetrics {
	summary := UltimateCFGMetrics{
		Basic:               m.Summary(),
		Halstead:            m.HalsteadComplexity(),
		Maintainability:     m.MaintainabilityIndex(),
		NPath:               m.NPathComplexity(),
		EssentialComplexity: m.EssentialComplexity(),
		FanAnalysis:         m.FanAnalysis(),
		Obfuscation:         m.ObfuscationDetection(),
		AIReadiness:         m.AIReadiness(),
	}
	summary.FusionIntelligence = runCFGFusionIntelligence(&summary)
	return summary
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func splitSmaliTokens(raw string) []string {
	// Split by whitespace and commas
	var tokens []string
	current := ""

	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == ' ' || ch == ',' || ch == '{' || ch == '}' {
			if current != "" {
				tokens = append(tokens, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}

	if current != "" {
		tokens = append(tokens, current)
	}

	return tokens
}

func isMetricsRegister(token string) bool {
	if len(token) < 2 {
		return false
	}
	return (token[0] == 'v' || token[0] == 'p') && token[1] >= '0' && token[1] <= '9'
}

func isMetricsConstant(token string) bool {
	if len(token) == 0 {
		return false
	}
	return token[0] == '#' || token[0] == '0' || token[0] == '-' || token[0] == '\''
}

func isMetricsReference(token string) bool {
	return len(token) > 0 && (token[0] == 'L' || token[0] == '[')
}

// ═══════════════════════════════════════════════════════════════════════════════
// CYCLOMATIC COMPLEXITY (from original)
// ═══════════════════════════════════════════════════════════════════════════════

func (m *Metrics) CyclomaticComplexity() int {
	if m.cfg == nil {
		return 0
	}

	e := len(m.cfg.Edges)
	n := len(m.cfg.Nodes)
	p := m.connectedComponents()

	return e - n + 2*p
}

func (m *Metrics) connectedComponents() int {
	if len(m.cfg.Nodes) == 0 {
		return 0
	}

	visited := make(map[int]bool)
	components := 0

	var dfs func(node *CFGNode)
	dfs = func(node *CFGNode) {
		if visited[node.ID] {
			return
		}
		visited[node.ID] = true

		for _, succ := range node.Successors {
			dfs(succ)
		}
		for _, pred := range node.Predecessors {
			dfs(pred)
		}
	}

	for _, node := range m.cfg.Nodes {
		if !visited[node.ID] {
			components++
			dfs(node)
		}
	}

	return components
}

// CognitiveComplexity (from original)
func (m *Metrics) CognitiveComplexity() int {
	if m.cfg == nil {
		return 0
	}

	complexity := 0

	for _, node := range m.cfg.Nodes {
		switch node.Type {
		case NodeTypeCondition, NodeTypeSwitch, NodeTypeGuard:
			complexity++
			nestingDepth := m.calculateStructuralNesting(node)
			complexity += nestingDepth

		case NodeTypeCatch:
			complexity++
		}

		if node.IsLoopHeader {
			complexity++
		}
	}

	return complexity
}

func (m *Metrics) calculateStructuralNesting(node *CFGNode) int {
	depth := 0

	dom := node.ImmediateDom
	for dom != nil {
		if dom.Type == NodeTypeCondition || dom.Type == NodeTypeGuard {
			depth++
		}
		dom = dom.ImmediateDom
	}

	return depth
}

// EstimatedPathCount (from original)
func (m *Metrics) EstimatedPathCount() int64 {
	if m.cfg == nil || m.cfg.Entry == nil {
		return 0
	}

	collapsedCFG := m.collapseLoops()
	return m.countDAGPaths(collapsedCFG)
}

type collapsedNode struct {
	id         int
	successors []int
	isExit     bool
}

func (m *Metrics) collapseLoops() map[int]*collapsedNode {
	collapsed := make(map[int]*collapsedNode)

	representative := make(map[int]int)
	for _, node := range m.cfg.Nodes {
		if node.LoopHeader != nil && node.LoopHeader != node {
			representative[node.ID] = node.LoopHeader.ID
		} else {
			representative[node.ID] = node.ID
		}
	}

	for _, node := range m.cfg.Nodes {
		rep := representative[node.ID]

		if collapsed[rep] == nil {
			collapsed[rep] = &collapsedNode{
				id:         rep,
				successors: make([]int, 0),
			}
		}

		for _, succ := range node.Successors {
			succRep := representative[succ.ID]
			if succRep != rep {
				if !containsInt(collapsed[rep].successors, succRep) {
					collapsed[rep].successors = append(collapsed[rep].successors, succRep)
				}
			}
		}

		if node.Type.IsTerminator() {
			collapsed[rep].isExit = true
		}
	}

	return collapsed
}

func (m *Metrics) countDAGPaths(collapsed map[int]*collapsedNode) int64 {
	if len(collapsed) == 0 {
		return 0
	}

	order := m.topologicalSort(collapsed)

	pathCount := make(map[int]int64)
	entryRep := m.cfg.Entry.ID
	if m.cfg.Entry.LoopHeader != nil {
		entryRep = m.cfg.Entry.LoopHeader.ID
	}
	pathCount[entryRep] = 1

	for _, id := range order {
		node := collapsed[id]
		if node == nil {
			continue
		}

		for _, succID := range node.successors {
			pathCount[succID] += pathCount[id]

			if pathCount[succID] > 1000000 {
				pathCount[succID] = 1000000
			}
		}
	}

	var total int64
	for id, node := range collapsed {
		if node.isExit {
			total += pathCount[id]
		}
	}

	return total
}

func (m *Metrics) topologicalSort(collapsed map[int]*collapsedNode) []int {
	visited := make(map[int]bool)
	var order []int

	var visit func(id int)
	visit = func(id int) {
		if visited[id] {
			return
		}
		visited[id] = true

		node := collapsed[id]
		if node != nil {
			for _, succ := range node.successors {
				visit(succ)
			}
		}

		order = append([]int{id}, order...)
	}

	for id := range collapsed {
		visit(id)
	}

	return order
}

// ExitDiversity (from original)
type ExitDiversity struct {
	TotalExits    int
	ReturnPaths   int
	ThrowPaths    int
	UniqueReturns int
	Reachability  map[*CFGNode]float64
}

func (m *Metrics) ExitDiversity() ExitDiversity {
	result := ExitDiversity{
		Reachability: make(map[*CFGNode]float64),
	}

	if m.cfg == nil {
		return result
	}

	result.TotalExits = len(m.cfg.Exits)
	result.ReturnPaths = len(m.cfg.ReturnExits)
	result.ThrowPaths = len(m.cfg.ThrowExits)

	for _, exit := range m.cfg.Exits {
		result.Reachability[exit] = m.calculateExitReachability(exit)
	}

	return result
}

func (m *Metrics) calculateExitReachability(exit *CFGNode) float64 {
	visited := make(map[int]bool)
	count := 0

	var dfs func(node *CFGNode)
	dfs = func(node *CFGNode) {
		if visited[node.ID] {
			return
		}
		visited[node.ID] = true
		count++

		for _, pred := range node.Predecessors {
			dfs(pred)
		}
	}

	dfs(exit)

	if len(m.cfg.Nodes) == 0 {
		return 0
	}

	return float64(count) / float64(len(m.cfg.Nodes))
}

// Summary (from original)
type CFGMetricsSummary struct {
	NodeCount            int
	EdgeCount            int
	CyclomaticComplexity int
	CognitiveComplexity  int
	ExitCount            int
	LoopCount            int
	MaxLoopDepth         int
	GuardCount           int
	FunnelCount          int
	EstimatedPaths       int64
	ConnectedComponents  int
}

func (m *Metrics) Summary() CFGMetricsSummary {
	summary := CFGMetricsSummary{
		NodeCount:            len(m.cfg.Nodes),
		EdgeCount:            len(m.cfg.Edges),
		CyclomaticComplexity: m.CyclomaticComplexity(),
		CognitiveComplexity:  m.CognitiveComplexity(),
		ExitCount:            len(m.cfg.Exits),
		EstimatedPaths:       m.EstimatedPathCount(),
		ConnectedComponents:  m.connectedComponents(),
	}

	for _, node := range m.cfg.Nodes {
		if node.IsLoopHeader {
			summary.LoopCount++
		}
		if node.LoopDepth > summary.MaxLoopDepth {
			summary.MaxLoopDepth = node.LoopDepth
		}
		if node.IsGuard {
			summary.GuardCount++
		}
		if node.IsFunnel {
			summary.FunnelCount++
		}
	}

	return summary
}

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
