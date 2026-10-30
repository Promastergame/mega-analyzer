package cfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/dexir"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DATA FLOW GRAPH (DFG) - CFG-BASED BACKWARD ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════
//
// НЕ runtime simulation.
// Это backward traversal по Control Flow Graph:
//   1. Идём назад по инструкциям внутри блока
//   2. Не нашли → идём в predecessor блоки (по CFG edges)
//   3. Depth limit предотвращает зацикливание
//
// Ключевая фича: правильная связка invoke-* → move-result
// ═══════════════════════════════════════════════════════════════════════════════

// Value представляет значение в регистре (результат анализа, не runtime state!)
type Value struct {
	SourceInstr *Instruction // Инструкция-источник
	Const       *string      // Константа (если есть)
	FromInvoke  string       // Метод вызова (для move-result)
	FromField   string       // Поле (для iget/sget)
	Reg         string       // Исходный регистр (для move)
	Confidence  float64      // Уверенность (0.0-1.0)
}

// TraceStep один шаг трейсинга
type TraceStep struct {
	Instruction *Instruction
	Register    string
	Value       Value
	Notes       string
}

// Condition описывает условие в if-* инструкции
type Condition struct {
	Opcode      string // if-eqz, if-nez, if-eq, etc.
	Register    string // регистр который проверяется (v0)
	TargetReg   string // для if-eq/if-ne — второй регистр
	TargetLabel string // метка перехода (:cond_0)
}

// String человекочитаемое описание условия
func (c Condition) String() string {
	switch c.Opcode {
	case "if-eqz":
		return c.Register + " == false"
	case "if-nez":
		return c.Register + " != false"
	case "if-eq":
		return c.Register + " == " + c.TargetReg
	case "if-ne":
		return c.Register + " != " + c.TargetReg
	case "if-lt":
		return c.Register + " < " + c.TargetReg
	case "if-ge":
		return c.Register + " >= " + c.TargetReg
	default:
		return c.Opcode + " " + c.Register
	}
}

// AnalysisHint аналитическая подсказка (не команда к действию!)
type AnalysisHint struct {
	Category    string  // "license_check", "debug_check", "anti_analysis"
	Observation string  // Что обнаружено
	Details     string  // Подробности
	Confidence  float64 // Уверенность 0-1
}

// LicenseCheckInfo обогащённая информация о проверке лицензии
type LicenseCheckInfo struct {
	Instruction *Instruction
	Condition   Condition      // Распарсенное условие
	Register    string         // Регистр в условии
	Trace       []TraceStep    // Цепочка откуда пришло значение
	Confidence  float64        // Общая уверенность
	Hints       []AnalysisHint // Аналитические подсказки (не патчи!)
}

// DFGInfo результат DFG анализа (для экспорта в ml пакет)
// ⚠️ ВНИМАНИЕ: Trace содержит внутренние ссылки на Instruction — это unstable API.
// Для использования в ml пакете ВСЕГДА проходить через convertDFGInfo()!
type DFGInfo struct {
	Available     bool        // true если анализ выполнен
	ConditionType string      // if-eqz, if-nez, etc
	ConditionText string      // человекочитаемо
	Register      string      // регистр в условии
	Trace         []TraceStep // полная цепочка (внутренняя структура!)
	Confidence    float64     // общая уверенность
}

// ═══════════════════════════════════════════════════════════════════════════════
// DFG ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

type DFGAnalyzer struct {
	cfg        *ControlFlowGraph
	lastInvoke *Instruction // parsing state (не runtime!): последний invoke для move-result
}

// NewDFGAnalyzer создаёт анализатор DFG
func NewDFGAnalyzer(cfg *ControlFlowGraph) *DFGAnalyzer {
	return &DFGAnalyzer{cfg: cfg}
}

// Analyze заполняет DFG-поля (DefRegs/UseRegs/ConstVal/InvokeRef/FieldRef/MoveSrc)
// Single linear pass — только парсинг, НЕ симуляция выполнения.
func (d *DFGAnalyzer) Analyze() {
	if d.cfg == nil || d.cfg.Method == nil {
		return
	}

	for _, instr := range d.cfg.Method.Instructions {
		d.analyzeInstruction(instr)
	}
}

// analyzeInstruction определяет Def/Use для одной инструкции.
// Все операнды берутся из типизированного IR (Dst/Srcs/Imm/Str/Method/Field),
// сырая строка инструкции больше не токенизируется.
//
// Примечание об эквивалентности: исторический строковый парсер требовал
// 3+ частей для field get/put, поэтому sget/sput (2 операнда) не
// аннотировались. Типизированная версия сохраняет эту семантику через
// проверку количества Srcs, чтобы наблюдаемый DFG-выход не менялся.
func (d *DFGAnalyzer) analyzeInstruction(instr *Instruction) {
	if instr.IR == nil {
		if len(instr.Operands) == 0 && instr.Raw != "" {
			op, ops := parseSmaliOpcode(instr.Raw)
			if instr.Opcode == "" {
				instr.Opcode = op
			}
			instr.Operands = ops
		}
		instr.IR = irFromLegacy(instr.Opcode, instr.Operands)
	}
	ir := instr.IR
	if ir == nil {
		return
	}
	op := ir.Op

	switch {
	// ── CONST ──────────────────────────────────────────────────────────────
	case op == dexir.OpConstString || op == dexir.OpConstStringJumbo:
		if ir.Dst != dexir.NoRegister {
			instr.DefRegs = []string{registerName(ir.Dst)}
			val := ir.Str
			instr.ConstVal = &val
		}

	case op == dexir.OpConstClass:
		if ir.Dst != dexir.NoRegister {
			instr.DefRegs = []string{registerName(ir.Dst)}
			val := ir.Type
			instr.ConstVal = &val
		}

	case isConstOp(op):
		// const/4, const/16, const, const/high16, const-wide*
		if ir.Dst != dexir.NoRegister {
			instr.DefRegs = []string{registerName(ir.Dst)}
			if ir.HasImm {
				val := renderConstValue(ir.Imm)
				instr.ConstVal = &val
			}
		}

	// ── MOVE-RESULT (💥 ключевой момент — связываем с lastInvoke) ─────────
	case op >= dexir.OpMoveResult && op <= dexir.OpMoveResultObject:
		if ir.Dst != dexir.NoRegister {
			instr.DefRegs = []string{registerName(ir.Dst)}
		}
		if d.lastInvoke != nil {
			instr.InvokeRef = d.lastInvoke.InvokeRef
		}
		d.lastInvoke = nil // move-result потребляет invoke

	// ── MOVE ───────────────────────────────────────────────────────────────
	case isMoveOp(op):
		if ir.Dst != dexir.NoRegister && len(ir.Srcs) > 0 {
			dst := registerName(ir.Dst)
			src := registerName(ir.Srcs[0])
			instr.DefRegs = []string{dst}
			instr.UseRegs = []string{src}
			instr.MoveSrc = src
		}

	// ── INVOKE ──────────────────────────────────────────────────────────────
	case ir.IsInvoke():
		for _, r := range ir.Srcs {
			if reg := registerName(r); reg != "" {
				instr.UseRegs = append(instr.UseRegs, reg)
			}
		}
		if ir.Method != nil {
			instr.InvokeRef = ir.Method.String()
		}
		d.lastInvoke = instr // запоминаем для следующего move-result

	// ── FIELD READ ──────────────────────────────────────────────────────────
	case isFieldGetOp(op):
		// sget не имеет объектного регистра → исторически не аннотировался
		if ir.Dst != dexir.NoRegister && len(ir.Srcs) >= 1 {
			instr.DefRegs = []string{registerName(ir.Dst)}
			instr.UseRegs = []string{registerName(ir.Srcs[0])}
			if ir.Field != nil {
				instr.FieldRef = ir.Field.String()
			}
		}

	// ── FIELD WRITE ─────────────────────────────────────────────────────────
	case isFieldPutOp(op):
		// sput имеет только 1 регистр → исторически не аннотировался
		if len(ir.Srcs) >= 2 {
			instr.UseRegs = []string{
				registerName(ir.Srcs[0]),
				registerName(ir.Srcs[1]),
			}
			if ir.Field != nil {
				instr.FieldRef = ir.Field.String()
			}
		}

	// ── CONDITIONAL ─────────────────────────────────────────────────────────
	case op >= dexir.OpIfEq && op <= dexir.OpIfLez:
		for _, r := range ir.Srcs {
			instr.UseRegs = append(instr.UseRegs, registerName(r))
		}

	// ── RETURN ─────────────────────────────────────────────────────────────
	case ir.IsReturn():
		if op != dexir.OpReturnVoid && len(ir.Srcs) > 0 {
			if reg := registerName(ir.Srcs[0]); reg != "" {
				instr.UseRegs = []string{reg}
			}
		}

	// ── ARRAY ───────────────────────────────────────────────────────────────
	case isArrayGetOp(op):
		if ir.Dst != dexir.NoRegister && len(ir.Srcs) >= 2 {
			instr.DefRegs = []string{registerName(ir.Dst)}
			instr.UseRegs = []string{
				registerName(ir.Srcs[0]),
				registerName(ir.Srcs[1]),
			}
		}

	case isArrayPutOp(op):
		if len(ir.Srcs) >= 3 {
			instr.UseRegs = []string{
				registerName(ir.Srcs[0]),
				registerName(ir.Srcs[1]),
				registerName(ir.Srcs[2]),
			}
		}

	// ── ARITHMETIC (3- и 2-операндные формы, включая /2addr и /litN) ──────
	case isDFGBinop(op):
		if ir.Dst != dexir.NoRegister {
			instr.DefRegs = []string{registerName(ir.Dst)}
		}
		for _, r := range ir.Srcs {
			instr.UseRegs = append(instr.UseRegs, registerName(r))
		}

	// ── INSTANCE ────────────────────────────────────────────────────────────
	case op == dexir.OpNewInstance:
		if ir.Dst != dexir.NoRegister {
			instr.DefRegs = []string{registerName(ir.Dst)}
		}

	case op == dexir.OpInstanceOf:
		if ir.Dst != dexir.NoRegister && len(ir.Srcs) >= 1 {
			instr.DefRegs = []string{registerName(ir.Dst)}
			instr.UseRegs = []string{registerName(ir.Srcs[0])}
		}

	case op == dexir.OpCheckCast:
		if ir.Dst != dexir.NoRegister {
			reg := registerName(ir.Dst)
			instr.DefRegs = []string{reg}
			instr.UseRegs = []string{reg}
		}
	}
}

// isFieldPutOp reports iput*/sput* opcodes.
func isFieldPutOp(op dexir.Opcode) bool {
	return (op >= dexir.OpIput && op <= dexir.OpIput+6) ||
		(op >= dexir.OpSput && op <= dexir.OpSput+6)
}

// isArrayPutOp reports aput* opcodes.
func isArrayPutOp(op dexir.Opcode) bool {
	return op >= dexir.OpAput && op <= dexir.OpAput+6
}

// isDFGBinop reports arithmetic/logical opcodes the DFG annotates:
// add/sub/mul/div/rem/and/or/xor across all type widths, including
// /2addr, /lit16 and /lit8 forms. Shifts (shl/shr/ushr) and rsub-int
// are intentionally excluded — the historical parser never covered them.
func isDFGBinop(op dexir.Opcode) bool {
	switch op.Name()[0] {
	case 'a', 's', 'm', 'd', 'r', 'o', 'x':
	default:
		return false
	}
	n := op.Name()
	for _, p := range binopPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

var binopPrefixes = []string{"add-", "sub-", "mul-", "div-", "rem-", "and-", "or-", "xor-"}

// ═══════════════════════════════════════════════════════════════════════════════
// TRACE — CFG Backward Analysis
// ═══════════════════════════════════════════════════════════════════════════════
//
// Находит источник значения в регистре, идя НАЗАД по CFG.
// НЕ симуляция — это поиск определения (def) регистра через граф.
// ═══════════════════════════════════════════════════════════════════════════════

// Trace находит цепочку от startInstr назад к источнику значения в reg.
// maxDepth ограничивает глубину (для защиты от циклов).
func (d *DFGAnalyzer) Trace(reg string, startInstr *Instruction, maxDepth int) []TraceStep {
	if d.cfg == nil || startInstr == nil || maxDepth <= 0 {
		return nil
	}

	// Ищем блок, содержащий startInstr — NodeByIdx может не иметь прямого маппинга
	// для всех индексов, поэтому ищем через перебор узлов
	var startBlock *CFGNode
	for _, node := range d.cfg.Nodes {
		if startInstr.Index >= node.StartIdx && startInstr.Index <= node.EndIdx {
			startBlock = node
			break
		}
	}
	if startBlock == nil {
		return nil
	}

	visited := make(map[int]bool) // block.ID → visited
	var steps []TraceStep

	// Ищем назад от инструкции ДО startInstr (т.е. Index-1)
	d.traceRegInBlock(reg, startBlock, startInstr.Index-1, maxDepth, visited, &steps)

	return steps
}

// traceRegInBlock ищет определение регистра в блоке, затем в predecessors.
func (d *DFGAnalyzer) traceRegInBlock(reg string, block *CFGNode, startIdx int, depth int, visited map[int]bool, steps *[]TraceStep) {
	if depth <= 0 || block == nil || visited[block.ID] {
		return
	}

	// Границы блока
	end := startIdx
	if end > block.EndIdx {
		end = block.EndIdx
	}

	// Идём назад по инструкциям внутри блока
	for i := end; i >= block.StartIdx; i-- {
		if i < 0 || d.cfg.Method == nil || i >= len(d.cfg.Method.Instructions) {
			continue
		}
		instr := d.cfg.Method.Instructions[i]
		if instr == nil {
			continue
		}

		// Проверяем: эта инструкция определяет наш регистр?
		for _, defReg := range instr.DefRegs {
			if defReg == reg {
				step := TraceStep{
					Instruction: instr,
					Register:    reg,
					Notes:       d.describeSource(instr),
				}
				*steps = append(*steps, step)

				// Если это move — продолжаем трейсить источник
				if instr.MoveSrc != "" && depth > 1 {
					d.traceRegInBlock(instr.MoveSrc, block, i-1, depth-1, visited, steps)
				}
				return // Нашли определение — останавливаемся
			}
		}
	}

	// Не нашли в этом блоке → идём в predecessors (по CFG)
	visited[block.ID] = true
	for _, pred := range block.Predecessors {
		d.traceRegInBlock(reg, pred, pred.EndIdx, depth-1, visited, steps)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LICENSE CHECK DETECTION (Z3-lite без Z3)
// ═══════════════════════════════════════════════════════════════════════════════

// FindLicenseChecks находит if-* которые проверяют license/premium.
func (d *DFGAnalyzer) FindLicenseChecks(maxDepth int) []LicenseCheckInfo {
	var checks []LicenseCheckInfo
	if d.cfg == nil || d.cfg.Method == nil {
		return checks
	}

	for _, instr := range d.cfg.Method.Instructions {
		if !strings.HasPrefix(instr.Opcode, "if-") {
			continue
		}

		// Парсим условие
		cond := d.parseCondition(instr)

		// Трейсим главный регистр условия
		trace := d.Trace(cond.Register, instr, maxDepth)
		conf := d.scoreLicenseTrace(trace)

		if conf >= 0.5 {
			check := LicenseCheckInfo{
				Instruction: instr,
				Condition:   cond,
				Register:    cond.Register,
				Trace:       trace,
				Confidence:  conf,
			}

			// Генерируем аналитические подсказки на основе анализа
			check.Hints = d.generateHints(check)

			checks = append(checks, check)
		}
	}
	return checks
}

// parseCondition парсит if-* инструкцию в структуру Condition
func (d *DFGAnalyzer) parseCondition(instr *Instruction) Condition {
	cond := Condition{
		Opcode: instr.Opcode,
	}

	// Регистры условия уже лежат в instr.UseRegs (типизированный анализ)
	if len(instr.UseRegs) >= 1 {
		cond.Register = instr.UseRegs[0]
	}
	if len(instr.UseRegs) >= 2 {
		cond.TargetReg = instr.UseRegs[1]
	}

	// Метка перехода — из типизированного IR
	if instr.IR != nil && instr.IR.BranchLabel != "" {
		cond.TargetLabel = ":" + instr.IR.BranchLabel
	}

	return cond
}

// generateHints генерирует аналитические подсказки (не команды!)
func (d *DFGAnalyzer) generateHints(check LicenseCheckInfo) []AnalysisHint {
	var hints []AnalysisHint

	// Анализируем Trace чтобы понять смысл проверки
	var hasInvoke bool
	var invokeName string
	var isBooleanResult bool

	for _, step := range check.Trace {
		if step.Instruction == nil {
			continue
		}

		// Нашли invoke в цепочке
		if step.Instruction.InvokeRef != "" {
			hasInvoke = true
			invokeName = step.Instruction.InvokeRef

			// Проверяем что возвращает boolean (Z)
			if strings.HasSuffix(invokeName, ")Z") {
				isBooleanResult = true
			}
		}
	}

	// Hint 1: Boolean метод типа isPremium()
	if hasInvoke && isBooleanResult {
		switch check.Condition.Opcode {
		case "if-eqz":
			// if-eqz v1 → проверка "если false"
			hints = append(hints, AnalysisHint{
				Category:    "license_check",
				Observation: "Boolean method checked for false",
				Details: "Method " + invokeName + " returns false → jump taken. " +
					"Invert condition or force true to bypass",
				Confidence: check.Confidence * 0.9,
			})

		case "if-nez":
			// if-nez v1 → проверка "если true"
			hints = append(hints, AnalysisHint{
				Category:    "license_check",
				Observation: "Boolean method checked for true",
				Details: "Method " + invokeName + " returns true → jump taken. " +
					"Replace with unconditional goto to always jump",
				Confidence: check.Confidence * 0.85,
			})
		}
	}

	// Hint 2: String constants
	for _, step := range check.Trace {
		if step.Instruction != nil && step.Instruction.ConstVal != nil {
			s := strings.ToLower(*step.Instruction.ConstVal)
			if strings.Contains(s, "premium") || strings.Contains(s, "license") {
				hints = append(hints, AnalysisHint{
					Category:    "string_comparison",
					Observation: "String comparison with license-related value",
					Details: "Compared against: '" + *step.Instruction.ConstVal + "'. " +
						"NOP or modify constant to bypass",
					Confidence: check.Confidence * 0.7,
				})
			}
		}
	}

	return hints
}

// scoreLicenseTrace вычисляет confidence что это проверка лицензии.
func (d *DFGAnalyzer) scoreLicenseTrace(trace []TraceStep) float64 {
	var conf float64
	for _, step := range trace {
		instr := step.Instruction
		if instr == nil {
			continue
		}

		// Константа со строкой "premium"/"license"...
		if instr.ConstVal != nil {
			s := strings.ToLower(*instr.ConstVal)
			if strings.Contains(s, "premium") || strings.Contains(s, "license") ||
				strings.Contains(s, "ispro") || strings.Contains(s, "full") {
				conf += 0.3
			}
		}

		// Invoke с подозрительным именем
		if instr.InvokeRef != "" {
			inv := strings.ToLower(instr.InvokeRef)
			if isLicenseRelated(inv) {
				conf += 0.5
			}
		}

		// Field с подозрительным именем
		if instr.FieldRef != "" {
			f := strings.ToLower(instr.FieldRef)
			if isLicenseRelated(f) {
				conf += 0.3
			}
		}
	}

	// === ОГРОМНОЕ УСИЛЕНИЕ (Z3 Integration) ===
	// Теперь мы не просто гадаем по именам, а отправляем реальный код на сервер!
	// (Если сервер работает, мы проверяем условие)
	smtExpr := d.generateSMTLib2(trace)
	if smtExpr != "" {
		z3Result := solveWithOmnisecServer(smtExpr)
		if z3Result == "sat" {
			conf += 0.4
		} else if z3Result == "unsat" {
			// Если условие недостижимо, это может быть opaque predicate!
			conf += 0.8
		}
	}

	if conf > 1.0 {
		conf = 1.0
	}
	return conf
}

// generateSMTLib2 превращает трейс DFG в сырой SMT-LIB2 код для Z3
func (d *DFGAnalyzer) generateSMTLib2(trace []TraceStep) string {
	if len(trace) == 0 {
		return ""
	}

	var sb strings.Builder
	// Базовая логика для демонстрации:
	// Объявляем целевой регистр как целое число
	targetReg := trace[0].Register
	sb.WriteString(fmt.Sprintf("(declare-const %s Int)\n", targetReg))

	hasCondition := false
	for _, step := range trace {
		instr := step.Instruction
		if instr == nil {
			continue
		}
		if instr.ConstVal != nil {
			// Если мы нашли константу, добавляем assertion что регистр равен константе
			// (в реальности тут нужно парсить int константы, мы делаем заглушку)
			val := *instr.ConstVal
			// Простейший эвристический парсинг 0x1, 0x0
			if val == "0x1" {
				sb.WriteString(fmt.Sprintf("(assert (= %s 1))\n", targetReg))
				hasCondition = true
			} else if val == "0x0" {
				sb.WriteString(fmt.Sprintf("(assert (= %s 0))\n", targetReg))
				hasCondition = true
			}
		}
	}

	if !hasCondition {
		return ""
	}

	sb.WriteString("(check-sat)\n")
	return sb.String()
}

// solveWithOmnisecServer отправляет SMT-выражение на наш Elixir+Rust сервер
func solveWithOmnisecServer(smtExpr string) string {
	payload := map[string]string{"expr": smtExpr}
	jsonData, _ := json.Marshal(payload)

	// URL сервера (пока хардкод)
	url := "http://localhost:4000/api/v1/symexec/solve"

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "error"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "error"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "error"
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "error"
	}

	if val, ok := result["result"].(string); ok {
		return val
	}
	return "error"
}

// emulateWithOmnisecServer отправляет native shellcode (ARM/x86) на эмуляцию в OmniSec Micro-Emulator
func emulateWithOmnisecServer(shellcode []byte) string {
	hexCode := fmt.Sprintf("%x", shellcode)
	payload := map[string]string{"shellcode_hex": hexCode}
	jsonData, _ := json.Marshal(payload)

	url := "http://localhost:4000/api/v1/microemu/emulate"

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "error"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "error"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "error"
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "error"
	}

	if val, ok := result["result"].(string); ok {
		return val
	}
	return "error"
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func (d *DFGAnalyzer) describeSource(instr *Instruction) string {
	switch {
	case instr.ConstVal != nil:
		return "const: " + *instr.ConstVal
	case instr.InvokeRef != "":
		return "invoke: " + instr.InvokeRef
	case instr.FieldRef != "":
		return "field: " + instr.FieldRef
	case instr.MoveSrc != "":
		return "move from: " + instr.MoveSrc
	default:
		return instr.Opcode
	}
}

// GetDFG возвращает DFGInfo для лучшей найденной проверки (или nil)
func (d *DFGAnalyzer) GetDFG(maxDepth int) *DFGInfo {
	checks := d.FindLicenseChecks(maxDepth)
	if len(checks) == 0 {
		return nil
	}

	// Находим лучшую по confidence
	var best *LicenseCheckInfo
	for i := range checks {
		if best == nil || checks[i].Confidence > best.Confidence {
			best = &checks[i]
		}
	}
	if best == nil {
		return nil
	}

	return &DFGInfo{
		Available:     true,
		ConditionType: best.Condition.Opcode,
		ConditionText: best.Condition.String(),
		Register:      best.Register,
		Trace:         best.Trace,
		Confidence:    best.Confidence,
	}
}

// isLicenseRelated проверяет содержит ли строку слова связанные с лицензией
func isLicenseRelated(s string) bool {
	keywords := []string{"premium", "license", "licensed", "ispro", "ispro",
		"checklicense", "haspurchased", "isvalid", "verify", "mlicensed", "unlocked"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}
