package deobfuscation

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/cfg"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DEOBFUSCATION ENGINE — Восстановление логики из обфусцированного кода
// ═══════════════════════════════════════════════════════════════════════════════
//
// Три уровня де-обфускации:
//   1. Control Flow Unflattening — разматывание диспетчерного switch
//   2. Opaque Predicate Resolution — вычисление подставных условий
//   3. Dead Code Elimination — удаление гарантированно мёртвого кода
//
// Каждый проход создаёт упрощённую копию CFG, оригинал не трогает.
// ═══════════════════════════════════════════════════════════════════════════════

// DeobfuscationResult содержит результаты де-обфускации метода
type DeobfuscationResult struct {
	MethodName string `json:"method_name"`
	ClassName  string `json:"class_name,omitempty"`

	// Control Flow Flattening
	CFFFDetected       bool     `json:"cff_detected"`
	CFFDispatcherNode  int      `json:"cff_dispatcher_node,omitempty"`
	CFFStateVariable   string   `json:"cff_state_variable,omitempty"`
	CFFRecoveredBlocks int      `json:"cff_recovered_blocks,omitempty"`
	CFFRecoveredEdges  []CFEdge `json:"cff_recovered_edges,omitempty"`
	CFFConfidence      float64  `json:"cff_confidence,omitempty"` // 0..1 likelihood the switch is a CFF dispatcher

	// Opaque Predicates
	OpaquePredicatesFound  int              `json:"opaque_predicates_found"`
	OpaquePredicateDetails []OpaquePredInfo `json:"opaque_predicate_details,omitempty"`
	DeadBranchesEliminated int              `json:"dead_branches_eliminated"`

	// Dead Code
	DeadNodesFound int   `json:"dead_nodes_found"`
	DeadNodeIDs    []int `json:"dead_node_ids,omitempty"`

	// Метрики.
	//
	// ProjectedReductionPercent is what the method WOULD shed if every
	// provably-dead branch were removed. These passes are analyses and do not
	// rewrite the graph, so nothing has been removed yet — the name says so
	// rather than implying a simplification that did not happen.
	OriginalComplexity        int     `json:"original_complexity"`
	SimplifiedComplexity      int     `json:"simplified_complexity"`
	ProjectedReductionPercent float64 `json:"projected_reduction_percent"`

	// Confidence — сводная оценка [0..1] того, что метод действительно
	// обфусцирован (агрегирует сигналы CFF, opaque-предикатов и мёртвого кода).
	Confidence float64 `json:"confidence"`

	// Строки
	RecoveredStrings []RecoveredString `json:"recovered_strings,omitempty"`

	// FusionIntelligence содержит результат Fusion Intelligence engine —
	// взвешенное, объяснимое ML-решение поверх всех структурных сигналов.
	// Nil только если анализ был пропущен (пустой граф).
	FusionIntelligence *FusionReport `json:"fusion_intelligence,omitempty"`
}

// IsObfuscated reports whether the analysis found any concrete evidence of
// obfuscation in the method.
func (r *DeobfuscationResult) IsObfuscated() bool {
	return r.CFFFDetected ||
		r.OpaquePredicatesFound > 0 ||
		r.DeadNodesFound > 0 ||
		len(r.RecoveredStrings) > 0
}

// CFEdge — восстановленное ребро CFG
type CFEdge struct {
	FromBlock int    `json:"from"`
	ToBlock   int    `json:"to"`
	Condition string `json:"condition,omitempty"`
}

// OpaquePredInfo — информация об обнаруженном opaque predicate
type OpaquePredInfo struct {
	NodeID       int    `json:"node_id"`
	ConditionStr string `json:"condition"`
	AlwaysTrue   bool   `json:"always_true"`
	AlwaysFalse  bool   `json:"always_false"`
	Reason       string `json:"reason"`
}

// RecoveredString — расшифрованная строка.
//
// DecryptedForm holds the plaintext only, with no annotation, so callers can
// feed it straight back into rule matching. The transform chain that produced
// it is reported separately in Transform.
type RecoveredString struct {
	EncryptedForm string  `json:"encrypted"`
	DecryptedForm string  `json:"decrypted"`
	Transform     string  `json:"transform,omitempty"` // e.g. "Base64 + XOR key 0x2F"
	DecryptorRef  string  `json:"decryptor_method"`
	Location      int     `json:"location"`
	Encoding      string  `json:"encoding,omitempty"` // base64 / hex / high-entropy / plain
	Entropy       float64 `json:"entropy,omitempty"`  // Shannon bits/byte of the literal
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEOBFUSCATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

// Engine — основной движок де-обфускации.
//
// All four passes are analyses: they measure and report, they never rewrite
// the graph. There is therefore no iteration count here — re-running an
// analysis over an unchanged graph can only produce the same answer. IR
// rewriting, and the fixpoint loop that goes with it, lives in the MIR/SSA
// pipeline in pkg/internal/apkloader.
type Engine struct {
	EnableCFF       bool
	EnableOpaque    bool
	EnableDeadCode  bool
	EnableStringDec bool
}

// Options — настройки движка де-обфускации
type Options struct {
	EnableCFF       bool
	EnableOpaque    bool
	EnableDeadCode  bool
	EnableStringDec bool
}

// NewEngine создаёт движок с заданными настройками
func NewEngine(opts Options) *Engine {
	return &Engine{
		EnableCFF:       opts.EnableCFF,
		EnableOpaque:    opts.EnableOpaque,
		EnableDeadCode:  opts.EnableDeadCode,
		EnableStringDec: opts.EnableStringDec,
	}
}

// NewDefaultEngine создаёт движок с настройками по умолчанию
func NewDefaultEngine() *Engine {
	return NewEngine(Options{
		EnableCFF:       true,
		EnableOpaque:    true,
		EnableDeadCode:  true,
		EnableStringDec: true,
	})
}

// Analyze выполняет полный анализ де-обфускации на CFG
func (e *Engine) Analyze(graph *cfg.ControlFlowGraph) *DeobfuscationResult {
	if graph == nil || len(graph.Nodes) == 0 {
		return &DeobfuscationResult{}
	}

	result := &DeobfuscationResult{
		MethodName: graph.MethodName,
		ClassName:  graph.ClassName,
	}

	// Считаем оригинальную сложность
	metrics := cfg.NewMetrics(graph)
	result.OriginalComplexity = metrics.CyclomaticComplexity()

	// ── Pass 1: Control Flow Flattening Detection ────────────
	if e.EnableCFF {
		e.detectCFF(graph, result)
	}

	// ── Pass 2: Opaque Predicate Resolution ──────────────────
	if e.EnableOpaque {
		e.resolveOpaquePredicates(graph, result)
	}

	// ── Pass 3: Dead Code Elimination ────────────────────────
	if e.EnableDeadCode {
		e.eliminateDeadCode(graph, result)
	}

	// ── Pass 4: String Decryption Detection ──────────────────
	if e.EnableStringDec {
		e.detectStringEncryption(graph, result)
	}

	// Projected simplification, not achieved simplification.
	//
	// These passes do not rewrite the graph, so nothing has actually been
	// removed. What we can state honestly is how much smaller the method WOULD
	// be if every provably-dead branch and unreachable block were dropped.
	// Cyclomatic complexity counts decision points, so only the branches
	// subtract from it; the previous formula also subtracted a count of nodes,
	// mixing two different units and reporting a reduction that had not
	// happened in either sense.
	result.SimplifiedComplexity = result.OriginalComplexity - result.DeadBranchesEliminated
	if result.SimplifiedComplexity < 1 {
		result.SimplifiedComplexity = 1
	}

	if result.OriginalComplexity > 0 {
		result.ProjectedReductionPercent = float64(result.OriginalComplexity-result.SimplifiedComplexity) /
			float64(result.OriginalComplexity) * 100.0
	}

	result.Confidence = e.scoreConfidence(result)

	// ── Pass 5: Fusion Intelligence ───────────────────────────
	// Runs last so it can project all prior signals into the ML feature space.
	result.FusionIntelligence = runFusionIntelligence(result)

	return result
}

// scoreConfidence aggregates the individual detector signals into a single
// bounded likelihood that the method is obfuscated. The weights are chosen so
// that a strong CFF match alone is highly suspicious, while weaker signals
// (a lone opaque predicate) accumulate more gradually.
func (e *Engine) scoreConfidence(r *DeobfuscationResult) float64 {
	score := 0.0
	if r.CFFFDetected {
		score += 0.5 * clamp01(r.CFFConfidence+0.4)
	}
	if r.OpaquePredicatesFound > 0 {
		score += 0.15 + 0.05*float64(min(r.OpaquePredicatesFound, 4))
	}
	if r.DeadNodesFound > 0 {
		score += 0.1 + 0.02*float64(min(r.DeadNodesFound, 5))
	}
	if len(r.RecoveredStrings) > 0 {
		score += 0.15 + 0.03*float64(min(len(r.RecoveredStrings), 5))
	}
	return clamp01(score)
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

// ═══════════════════════════════════════════════════════════════════════════════
// PASS 1: CONTROL FLOW FLATTENING DETECTION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Control Flow Flattening работает так:
//   1. Один «диспетчерный» switch контролирует все блоки
//   2. Переменная состояния (state var) определяет следующий блок
//   3. Каждый блок в конце обновляет state var и прыгает обратно на switch
//
// Мы детектим этот паттерн и пытаемся извлечь реальные связи между блоками.
// ═══════════════════════════════════════════════════════════════════════════════

func (e *Engine) detectCFF(graph *cfg.ControlFlowGraph, result *DeobfuscationResult) {
	// A method may contain several switch statements; the real CFF dispatcher
	// is the one with the strongest signal, so we score every candidate and
	// keep the best rather than committing to the first match.
	var best *cfg.CFGNode
	var bestConf float64

	for _, node := range graph.Nodes {
		if node.Type != cfg.NodeTypeSwitch || node.SwitchInfo == nil {
			continue
		}

		// CFF обычно: switch с ≥5 кейсами внутри цикла.
		if len(node.SwitchInfo.Targets) < cffMinCases {
			continue
		}

		inLoop := node.LoopDepth > 0 || e.hasBackEdge(node)
		if !inLoop {
			continue
		}

		conf := e.scoreCFFDispatcher(graph, node)
		if conf > bestConf {
			bestConf = conf
			best = node
		}
	}

	if best == nil {
		return
	}

	result.CFFFDetected = true
	result.CFFDispatcherNode = best.ID
	result.CFFStateVariable = e.findStateVariable(best)
	result.CFFRecoveredEdges = e.recoverCFFEdges(graph, best)
	result.CFFRecoveredBlocks = len(best.SwitchInfo.Targets)
	result.CFFConfidence = bestConf
}

// scoreCFFDispatcher estimates, in [0,1], how likely a switch node is a
// control-flow-flattening dispatcher. Signals: number of cases (dense
// dispatchers are stronger evidence), whether it sits in a loop, and how many
// case blocks write a recognisable next-state constant.
func (e *Engine) scoreCFFDispatcher(graph *cfg.ControlFlowGraph, node *cfg.CFGNode) float64 {
	targets := node.SwitchInfo.Targets
	score := 0.0

	// Case density: 5 cases → 0.30, saturating at ~15 cases → 0.50.
	score += 0.30 + 0.02*float64(min(len(targets)-cffMinCases, 10))

	if node.LoopDepth > 0 {
		score += 0.25
	} else if e.hasBackEdge(node) {
		score += 0.15
	}

	// Fraction of case blocks that assign a next-state constant back into the
	// state variable — the defining fingerprint of a flattened switch.
	assigns := 0
	for _, t := range targets {
		tn := graph.GetNode(t.TargetID)
		if tn == nil {
			continue
		}
		if e.findNextStateAssignment(tn, node) >= 0 {
			assigns++
		}
	}
	if len(targets) > 0 {
		score += 0.25 * (float64(assigns) / float64(len(targets)))
	}

	return clamp01(score)
}

// hasBackEdge проверяет наличие обратного ребра на данный узел
func (e *Engine) hasBackEdge(node *cfg.CFGNode) bool {
	for _, pred := range node.Predecessors {
		// Если предшественник имеет ID больше текущей ноды —
		// вероятно, это back-edge (при условии RPO нумерации)
		if pred.RPONumber > node.RPONumber {
			return true
		}
	}
	return false
}

// findStateVariable ищет переменную состояния (register)
func (e *Engine) findStateVariable(dispatcher *cfg.CFGNode) string {
	// State variable обычно определяется во всех target-блоках диспетчера
	// и используется в самом dispatcher

	if dispatcher.Condition != nil && dispatcher.Condition.Register1 != "" {
		return dispatcher.Condition.Register1
	}

	// Проверяем switch key register
	if dispatcher.SwitchInfo != nil && dispatcher.SwitchInfo.Register != "" {
		return dispatcher.SwitchInfo.Register
	}

	return ""
}

// recoverCFFEdges пытается восстановить реальные рёбра графа из CFF
func (e *Engine) recoverCFFEdges(graph *cfg.ControlFlowGraph, dispatcher *cfg.CFGNode) []CFEdge {
	var edges []CFEdge

	if dispatcher.SwitchInfo == nil {
		return edges
	}

	// Для каждого target-блока анализируем, куда он устанавливает
	// state variable (= какой блок является его реальным преемником)
	targets := dispatcher.SwitchInfo.Targets
	for i, target := range targets {
		targetNode := graph.GetNode(target.TargetID)
		if targetNode == nil {
			continue
		}

		// Ищем в инструкциях блока: const vX, <next_state>
		nextState := e.findNextStateAssignment(targetNode, dispatcher)

		if nextState >= 0 && nextState < len(targets) {
			edges = append(edges, CFEdge{
				FromBlock: i,
				ToBlock:   nextState,
				Condition: fmt.Sprintf("case_%d → case_%d", i, nextState),
			})
		}
	}

	return edges
}

// findNextStateAssignment ищет присваивание state variable в блоке
func (e *Engine) findNextStateAssignment(node *cfg.CFGNode, dispatcher *cfg.CFGNode) int {
	stateVar := e.findStateVariable(dispatcher)
	if stateVar == "" {
		return -1
	}

	// Ищем: const/4 vX, <value> или const/16 vX, <value>
	for i := len(node.Instructions) - 1; i >= 0; i-- {
		instr := node.Instructions[i]

		if !strings.HasPrefix(instr.Opcode, "const") {
			continue
		}

		// Ищем присваивание state variable и извлекаем его значение.
		if !assignsRegister(instr.Raw, stateVar) {
			continue
		}
		if val, ok := parseSmaliInt(lastOperand(instr.Raw)); ok {
			return int(val)
		}
	}

	return -1
}

// assignsRegister reports whether the instruction's destination register (the
// first operand after the opcode) is reg. This avoids false matches where the
// register name appears only inside the immediate or a type descriptor.
func assignsRegister(raw, reg string) bool {
	fields := strings.Fields(raw)
	if len(fields) < 2 {
		return false
	}
	dst := strings.TrimSuffix(fields[1], ",")
	return dst == reg
}

// ═══════════════════════════════════════════════════════════════════════════════
// PASS 2: OPAQUE PREDICATE RESOLUTION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Opaque predicates — условия, результат которых известен заранее:
//   • const vX, 1; if-eqz vX → ВСЕГДА false (vX = 1 ≠ 0)
//   • const vX, 0; if-nez vX → ВСЕГДА false (vX = 0, not ≠ 0)
//   • (x*x + x) % 2 == 0    → ВСЕГДА true (математический инвариант)
//   • Две ветки ведут в одну ноду → бессмысленное условие
// ═══════════════════════════════════════════════════════════════════════════════

func (e *Engine) resolveOpaquePredicates(graph *cfg.ControlFlowGraph, result *DeobfuscationResult) {
	for _, node := range graph.Nodes {
		if node.Condition == nil || node.Type != cfg.NodeTypeCondition {
			continue
		}

		// ── Check 1: обе ветки ведут в одну ноду ─────────────
		if len(node.Successors) == 2 && node.Successors[0] == node.Successors[1] {
			result.OpaquePredicatesFound++
			result.DeadBranchesEliminated++
			result.OpaquePredicateDetails = append(result.OpaquePredicateDetails, OpaquePredInfo{
				NodeID:       node.ID,
				ConditionStr: fmt.Sprintf("%s %s", node.Condition.Register1, node.Condition.Op.String()),
				AlwaysTrue:   true,
				AlwaysFalse:  true,
				Reason:       "Both branches lead to the same target — condition is irrelevant",
			})
			continue
		}

		// ── Check 2: const → immediate condition ─────────────
		if info := e.checkConstantCondition(node); info != nil {
			result.OpaquePredicatesFound++
			result.DeadBranchesEliminated++
			result.OpaquePredicateDetails = append(result.OpaquePredicateDetails, *info)
			continue
		}

		// ── Check 3: сравнение значения с самим собой ─────────
		if node.Condition.Register1 != "" &&
			node.Condition.Register1 == node.Condition.Register2 {
			isAlwaysTrue := false
			switch node.Condition.Op {
			case cfg.CondEq, cfg.CondLe, cfg.CondGe:
				isAlwaysTrue = true
			}

			if isAlwaysTrue {
				result.OpaquePredicatesFound++
				result.DeadBranchesEliminated++
				result.OpaquePredicateDetails = append(result.OpaquePredicateDetails, OpaquePredInfo{
					NodeID:       node.ID,
					ConditionStr: fmt.Sprintf("%s %s %s", node.Condition.Register1, node.Condition.Op.String(), node.Condition.Register2),
					AlwaysTrue:   true,
					Reason: fmt.Sprintf("Comparing %s with itself using %s — always true",
						node.Condition.Register1, node.Condition.Op),
				})
			}
		}
	}
}

// checkConstantCondition проверяет условие, где операнд — известная константа
func (e *Engine) checkConstantCondition(node *cfg.CFGNode) *OpaquePredInfo {
	if node.Condition == nil {
		return nil
	}

	// Both sides constant: actually evaluate the comparison. Previously this
	// branch asserted AlwaysTrue unconditionally, so `const v0,1; const v1,2;
	// if-eq v0,v1` was reported as always-true — half the verdicts here were
	// inverted, and each one also incremented DeadBranchesEliminated.
	if node.Condition.LHS != nil && node.Condition.LHS.Kind == cfg.ValueConst &&
		node.Condition.RHS != nil && node.Condition.RHS.Kind == cfg.ValueConst {
		lhs, lok := constAsInt(node.Condition.LHS)
		rhs, rok := constAsInt(node.Condition.RHS)
		if !lok || !rok {
			// Non-integer constants (strings, nulls): the comparison is still
			// predetermined, but we cannot say in which direction. Claiming a
			// direction would be a guess, so report nothing.
			return nil
		}
		taken, ok := evalIntCondition(node.Condition.Op, lhs, rhs)
		if !ok {
			return nil
		}
		return &OpaquePredInfo{
			NodeID:       node.ID,
			ConditionStr: fmt.Sprintf("%s %s %s", node.Condition.Register1, node.Condition.Op.String(), node.Condition.Register2),
			AlwaysTrue:   taken,
			AlwaysFalse:  !taken,
			Reason: fmt.Sprintf("both operands are constants (%d %s %d) — always %v",
				lhs, node.Condition.Op, rhs, taken),
		}
	}

	// Ищем const-определение register'а перед if-eqz/if-nez
	cond := node.Condition
	if !cond.Op.IsZeroCheck() || cond.Register1 == "" {
		return nil
	}
	if len(node.Predecessors) == 0 {
		return nil
	}

	// The register must carry the same constant on EVERY path into this node.
	// Agreeing on one predecessor proves nothing when another can reach the
	// branch with a different value, and a redefinition after the const kills
	// the fact entirely — both were previously ignored.
	var (
		agreedZero bool
		agreedStr  string
		first      = true
	)
	for _, prev := range node.Predecessors {
		val, valStr, ok := lastConstValueIn(prev, cond.Register1)
		if !ok {
			return nil
		}
		isZero := val == 0
		if first {
			agreedZero, agreedStr, first = isZero, valStr, false
			continue
		}
		if isZero != agreedZero {
			return nil
		}
	}

	switch cond.Op {
	case cfg.CondEqZero:
		return &OpaquePredInfo{
			NodeID:       node.ID,
			ConditionStr: fmt.Sprintf("%s %s %s", cond.Register1, cond.Op.String(), cond.Register2),
			AlwaysTrue:   agreedZero,
			AlwaysFalse:  !agreedZero,
			Reason: fmt.Sprintf("const %s = %s on all %d predecessor(s); if-eqz → always %v",
				cond.Register1, agreedStr, len(node.Predecessors), agreedZero),
		}
	case cfg.CondNeZero:
		return &OpaquePredInfo{
			NodeID:       node.ID,
			ConditionStr: fmt.Sprintf("%s %s %s", cond.Register1, cond.Op.String(), cond.Register2),
			AlwaysTrue:   !agreedZero,
			AlwaysFalse:  agreedZero,
			Reason: fmt.Sprintf("const %s = %s on all %d predecessor(s); if-nez → always %v",
				cond.Register1, agreedStr, len(node.Predecessors), !agreedZero),
		}
	}

	return nil
}

// lastConstValueIn walks a block backwards looking for the definition of reg.
// It returns the constant only when the LAST instruction to write reg is a
// const. Any other write (arithmetic, move-result, aget, invoke result) kills
// the fact: scanning past it, as the previous code did by skipping every
// non-const opcode, "proved" things like `const v0,1; add-int v0,v0,v1;
// if-eqz v0`.
func lastConstValueIn(block *cfg.CFGNode, reg string) (value int64, raw string, ok bool) {
	for i := len(block.Instructions) - 1; i >= 0; i-- {
		instr := block.Instructions[i]
		if !assignsRegister(instr.Raw, reg) {
			continue
		}
		if !strings.HasPrefix(instr.Opcode, "const") {
			return 0, "", false // killed by a non-const definition
		}
		valStr := lastOperand(instr.Raw)
		val, parsed := parseSmaliInt(valStr)
		if !parsed {
			return 0, "", false
		}
		return val, valStr, true
	}
	return 0, "", false // reg not defined in this block
}

// constAsInt extracts an integer from a constant ValueRef.
func constAsInt(v *cfg.ValueRef) (int64, bool) {
	switch c := v.ConstValue.(type) {
	case int:
		return int64(c), true
	case int32:
		return int64(c), true
	case int64:
		return c, true
	case string:
		return parseSmaliInt(c)
	default:
		return 0, false
	}
}

// evalIntCondition evaluates a two-operand integer comparison. It reports
// ok=false for zero-check ops, which do not belong on this path.
func evalIntCondition(op cfg.ConditionOp, lhs, rhs int64) (taken, ok bool) {
	switch op {
	case cfg.CondEq:
		return lhs == rhs, true
	case cfg.CondNe:
		return lhs != rhs, true
	case cfg.CondLt:
		return lhs < rhs, true
	case cfg.CondGe:
		return lhs >= rhs, true
	case cfg.CondGt:
		return lhs > rhs, true
	case cfg.CondLe:
		return lhs <= rhs, true
	default:
		return false, false
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PASS 3: DEAD CODE ELIMINATION
// ═══════════════════════════════════════════════════════════════════════════════

func (e *Engine) eliminateDeadCode(graph *cfg.ControlFlowGraph, result *DeobfuscationResult) {
	if graph.Entry == nil {
		return
	}

	// BFS от Entry
	reachable := make(map[int]bool, len(graph.Nodes))
	queue := []*cfg.CFGNode{graph.Entry}
	reachable[graph.Entry.ID] = true

	for head := 0; head < len(queue); head++ {
		current := queue[head]
		queue[head] = nil // free reference for GC

		for _, succ := range current.Successors {
			if !reachable[succ.ID] {
				reachable[succ.ID] = true
				queue = append(queue, succ)
			}
		}
	}

	// Находим недоступные узлы
	for _, node := range graph.Nodes {
		if !reachable[node.ID] {
			result.DeadNodesFound++
			result.DeadNodeIDs = append(result.DeadNodeIDs, node.ID)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PASS 4: STRING ENCRYPTION DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

// decryptorLookahead bounds how far past a const-string we search for the
// invoke that consumes it. Real decryptor call sites load a key or an index
// between the literal and the call (`const-string v0, ".."; const/4 v1, 0x3;
// invoke-static {v0, v1}, ..`), so requiring immediate adjacency missed the
// common shapes. The window is small because the pairing is a local idiom;
// widening it further only buys unrelated invokes.
const decryptorLookahead = 6

// detectStringEncryption recovers plaintext from encrypted string literals.
//
// Every const-string that looks encrypted is attempted, whether or not a
// decryptor call follows: the literal may be consumed in another block, passed
// to a virtual method, or stored in a field. When an invoke does follow within
// decryptorLookahead instructions it is recorded as the candidate decryptor so
// the report can point at it.
func (e *Engine) detectStringEncryption(graph *cfg.ControlFlowGraph, result *DeobfuscationResult) {
	for _, node := range graph.Nodes {
		for i := 0; i < len(node.Instructions); i++ {
			instr := node.Instructions[i]

			if instr.Opcode != "const-string" && instr.Opcode != "const-string/jumbo" {
				continue
			}

			strVal := e.extractStringConstValue(instr.Raw)
			if !e.looksEncrypted(strVal) {
				continue
			}

			plain, transform := tryDecryptString(strVal)
			if plain == "" {
				// Nothing readable came out. Recording the literal anyway would
				// flood the report with every high-entropy constant in the APK.
				continue
			}

			result.RecoveredStrings = append(result.RecoveredStrings, RecoveredString{
				EncryptedForm: strVal,
				DecryptedForm: plain,
				Transform:     transform,
				DecryptorRef:  e.findDecryptorRef(node.Instructions, i),
				Location:      instr.Index,
				Encoding:      classifyEncoding(strVal).String(),
				Entropy:       shannonEntropy([]byte(strVal)),
			})
		}
	}
}

// findDecryptorRef returns the method reference of the first invoke within
// decryptorLookahead instructions after start, or "" when none follows.
func (e *Engine) findDecryptorRef(instructions []cfg.InstructionRef, start int) string {
	end := start + 1 + decryptorLookahead
	if end > len(instructions) {
		end = len(instructions)
	}
	for j := start + 1; j < end; j++ {
		if strings.HasPrefix(instructions[j].Opcode, "invoke-") {
			return e.extractMethodRef(instructions[j].Raw)
		}
	}
	return ""
}

// extractStringConstValue извлекает значение строки из const-string инструкции
func (e *Engine) extractStringConstValue(raw string) string {
	idx := strings.Index(raw, "\"")
	if idx < 0 {
		return ""
	}
	end := strings.LastIndex(raw, "\"")
	if end <= idx {
		return ""
	}
	return raw[idx+1 : end]
}

// extractMethodRef извлекает ссылку на метод из invoke инструкции
func (e *Engine) extractMethodRef(raw string) string {
	// invoke-static {v0}, Lcom/example/Decrypt;->decode(Ljava/lang/String;)Ljava/lang/String;
	idx := strings.Index(raw, "L")
	if idx < 0 {
		return ""
	}
	return raw[idx:]
}

// looksEncrypted проверяет, выглядит ли строка зашифрованной.
//
// A literal is treated as suspicious when it is a long Base64/hex blob, when
// its character diversity is unusually high, or when it carries a significant
// fraction of non-printable bytes.
func (e *Engine) looksEncrypted(s string) bool {
	if len(s) < minEncryptedLen {
		return false
	}

	// Count by rune, not by byte. A byte loop treats every continuation byte of
	// a multi-byte UTF-8 sequence as non-printable, so any literal in Cyrillic,
	// CJK or emoji tripped the non-printable gate below and got dragged through
	// the whole XOR search. Legitimate non-Latin UI strings are the common case
	// in real APKs, not the exception.
	nonPrintable, runeCount := 0, 0
	for _, r := range s {
		runeCount++
		if r == utf8.RuneError || r < 32 || r == 127 {
			nonPrintable++
		}
	}
	if runeCount == 0 {
		return false
	}

	// Note: isBase64Charset also accepts the URL-safe '-'/'_' variants, which
	// the classic Base64 alphabet does not include; both are valid encodings
	// used in the wild and either is equally suspicious here.
	const longBlob = 16
	return (isBase64Charset(s) && len(s) >= longBlob) ||
		(isHexCharset(s) && len(s) >= longBlob) ||
		uniqueRuneRatio(s) > highEntropyUniqueRatio ||
		nonPrintable > runeCount/4
}
