// ═══════════════════════════════════════════════════════════════════════════════
// GATE DETECTOR — определяет "это реально gate или просто data method"
//
// Проблема: система считает любой boolean метод с if-условием "gate".
// Результат: 4788 точек, большинство — equals(), hashCode(), геттеры.
//
// Решение: проверяем 3 критерия:
//   1. RETURN AFFECTS CONTROL FLOW — результат используется в if/throw/exit
//   2. HAS MULTIPLE BRANCHES — есть разные return ветки (не always-const)
//   3. USED BY CALLERS — метод вызывается из других методов (не dead code)
//
// Только если все 3 = true → это REAL GATE → high score.
// Если хоть один false → score penalty или complete filter.
// ═══════════════════════════════════════════════════════════════════════════════

package ml

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// GateType — классификация "типа ворот"
type GateType int

const (
	GateTypeUnknown         GateType = iota
	GateTypeSecurityControl          // Проверка лицензии, подписи, root
	GateTypeFlowControl              // UI flow: showXxx(), isStepXxx()
	GateTypeDataAccessor             // equals, hashCode, toString, геттеры
	GateTypeBusinessLogic            // Проверка бизнес-правил (не security)
)

// GateAnalysis — результат анализа "gate-ness"
type GateAnalysis struct {
	IsRealGate               bool     `json:"is_real_gate"`
	GateType                 GateType `json:"gate_type"`
	ReturnAffectsControlFlow bool     `json:"return_affects_control_flow"`
	HasMultipleBranches      bool     `json:"has_multiple_branches"`
	HasCallers               bool     `json:"has_callers"`
	IsUtilityMethod          bool     `json:"is_utility_method"`
	IsDataClassMethod        bool     `json:"is_data_class_method"`
	PenaltyReasons           []string `json:"penalty_reasons,omitempty"`
	Confidence               float64  `json:"confidence"`
}

// GateDetector — детектор реальных gate'ов
type GateDetector struct {
	// CallGraph для проверки callers
	callGraph *types.CallGraph
	// Минимальное количество callers для признания "used"
	minCallers int
}

// NewGateDetector создает детектор
func NewGateDetector(cg *types.CallGraph) *GateDetector {
	return &GateDetector{
		callGraph:  cg,
		minCallers: 1, // Достаточно 1 caller'а
	}
}

// Analyze определяет, является ли метод реальным gate'ом
func (gd *GateDetector) Analyze(mi *MethodInfo) *GateAnalysis {
	analysis := &GateAnalysis{
		PenaltyReasons: make([]string, 0),
		Confidence:     1.0,
	}

	if mi == nil {
		analysis.PenaltyReasons = append(analysis.PenaltyReasons, "nil method")
		analysis.Confidence = 0
		return analysis
	}

	// 1. Определяем GateType по сигнатуре и имени
	analysis.GateType = gd.classifyGateType(mi)
	analysis.IsDataClassMethod = gd.isDataClassMethod(mi)
	analysis.IsUtilityMethod = gd.isUtilityMethod(mi)

	// 2. Проверяем: return affects control flow?
	analysis.ReturnAffectsControlFlow = gd.checkReturnAffectsControlFlow(mi)
	if !analysis.ReturnAffectsControlFlow {
		analysis.PenaltyReasons = append(analysis.PenaltyReasons,
			"return value not used in control flow (if/throw/exit)")
	}

	// 3. Проверяем: has multiple branches?
	analysis.HasMultipleBranches = gd.checkMultipleBranches(mi)
	if !analysis.HasMultipleBranches {
		analysis.PenaltyReasons = append(analysis.PenaltyReasons,
			"single return path (always const or trivial)")
	}

	// 4. Проверяем: has callers?
	analysis.HasCallers = gd.checkHasCallers(mi)
	if !analysis.HasCallers {
		analysis.PenaltyReasons = append(analysis.PenaltyReasons,
			"no callers (dead code or unreachable)")
	}

	// 5. Определяем: is real gate?
	// ВСЕ 3 критерия должны быть true
	analysis.IsRealGate = analysis.ReturnAffectsControlFlow &&
		analysis.HasMultipleBranches &&
		analysis.HasCallers &&
		!analysis.IsDataClassMethod &&
		!analysis.IsUtilityMethod

	// 6. Рассчитываем confidence
	analysis.Confidence = gd.calculateConfidence(analysis)

	return analysis
}

// classifyGateType определяет тип gate по имени и контексту
func (gd *GateDetector) classifyGateType(mi *MethodInfo) GateType {
	nameLower := strings.ToLower(mi.Name)
	sigLower := strings.ToLower(mi.FullSignature)
	classLower := strings.ToLower(mi.ClassName)

	// DATA CLASS METHODS — точно не gates
	dataPatterns := []string{
		"equals", "hashcode", "tostring", "compareto",
		"clone", "copy", "get", "set", "isvalid", "isinitialized",
	}
	for _, p := range dataPatterns {
		if strings.Contains(nameLower, p) {
			return GateTypeDataAccessor
		}
	}

	// SECURITY CONTROL — высокий приоритет
	securityPatterns := []string{
		"islicensed", "ispremium", "ispro", "checklicense",
		"verify", "authenticate", "authorize", "validate",
		"issigned", "checksignature", "verifyintegrity",
		"isrooted", "isdebug", "isemulator", "istampered",
	}
	for _, p := range securityPatterns {
		if strings.Contains(nameLower, p) || strings.Contains(sigLower, p) {
			return GateTypeSecurityControl
		}
	}

	// FLOW CONTROL — UI/UX gates
	flowPatterns := []string{
		"show", "hide", "enable", "disable",
		"can", "should", "may", "allowed",
		"isstep", "isfirst", "islast", "iscurrent",
		"haspermission", "isaccessible",
	}
	for _, p := range flowPatterns {
		if strings.Contains(nameLower, p) {
			return GateTypeFlowControl
		}
	}

	// Context-based: классы с license/premium/auth
	if strings.Contains(classLower, "license") ||
		strings.Contains(classLower, "premium") ||
		strings.Contains(classLower, "auth") ||
		strings.Contains(classLower, "security") ||
		strings.Contains(classLower, "protection") {
		return GateTypeSecurityControl
	}

	return GateTypeBusinessLogic
}

// isDataClassMethod проверяет data-class методы
func (gd *GateDetector) isDataClassMethod(mi *MethodInfo) bool {
	nameLower := strings.ToLower(mi.Name)

	// Стандартные data class методы
	if nameLower == "equals" ||
		nameLower == "hashcode" ||
		nameLower == "tostring" ||
		nameLower == "clone" ||
		nameLower == "compareto" ||
		nameLower == "containskey" ||
		nameLower == "containsvalue" ||
		nameLower == "isempty" ||
		nameLower == "size" ||
		nameLower == "clear" ||
		nameLower == "remove" ||
		nameLower == "putall" ||
		nameLower == "iterator" {
		return true
	}

	// Геттеры/сеттеры
	if strings.HasPrefix(nameLower, "get") ||
		strings.HasPrefix(nameLower, "set") ||
		strings.HasPrefix(nameLower, "is") && len(mi.Name) > 2 && mi.Name[2] >= 'A' && mi.Name[2] <= 'Z' {
		// isXxx где Xxx — PropertyName (isEnabled, isValid) — геттер
		// но isStepXxx — flow control
		if !strings.Contains(nameLower, "step") &&
			!strings.Contains(nameLower, "allowed") &&
			!strings.Contains(nameLower, "permitted") {
			return true
		}
	}

	return false
}

// isUtilityMethod проверяет utility методы
func (gd *GateDetector) isUtilityMethod(mi *MethodInfo) bool {
	nameLower := strings.ToLower(mi.Name)

	// Конвертеры и парсеры
	utilityPatterns := []string{
		"parse", "format", "convert", "transform",
		"encode", "decode", "serialize", "deserialize",
		"copy", "merge", "join", "split", "trim",
		"create", "build", "make", "new",
	}
	for _, p := range utilityPatterns {
		if strings.HasPrefix(nameLower, p) {
			return true
		}
	}

	// Static helpers
	if mi.IsStatic && strings.Contains(nameLower, "util") {
		return true
	}

	return false
}

// checkReturnAffectsControlFlow проверяет используется ли return в if/throw/exit
func (gd *GateDetector) checkReturnAffectsControlFlow(mi *MethodInfo) bool {
	if len(mi.RawBody) == 0 {
		return false
	}

	// Симуляция: проверяем есть ли разные return пути
	// В реальном анализе здесь был бы inter-procedural analysis

	returnPaths := gd.analyzeReturnPaths(mi)

	// Если есть только один return path — return не влияет на control flow
	if len(returnPaths) <= 1 {
		return false
	}

	// Если return values разные (true/false или разные константы)
	hasDifferentValues := gd.hasDifferentReturnValues(mi)

	return hasDifferentValues
}

// returnPath описывает путь до return
type returnPath struct {
	value      string
	condition  string
	isConstant bool
}

// analyzeReturnPaths анализирует пути до return
func (gd *GateDetector) analyzeReturnPaths(mi *MethodInfo) []returnPath {
	paths := make([]returnPath, 0)

	// Ищем return инструкции
	for _, line := range mi.RawBody {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "return") {
			continue
		}

		// Извлекаем return value
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			val := parts[1]
			paths = append(paths, returnPath{
				value:      val,
				isConstant: gd.isConstantValue(val),
			})
		}
	}

	// Анализируем условия перед return — без Join, скан по слайсу
	if rawBodyContains(mi.RawBody, "if-") {
		// Есть conditional logic — return может зависеть от условий
		// Это хороший признак gate
		for i := range paths {
			paths[i].condition = "conditional"
		}
	}

	return paths
}

// isConstantValue проверяет является ли value константой
func (gd *GateDetector) isConstantValue(val string) bool {
	val = strings.TrimSpace(val)
	// const/4, const/16, const-string, etc.
	return strings.HasPrefix(val, "0x") ||
		val == "0" || val == "1" ||
		strings.HasPrefix(val, "v") == false // не register = likely constant
}

// hasDifferentReturnValues проверяет возвращаются ли разные значения
func (gd *GateDetector) hasDifferentReturnValues(mi *MethodInfo) bool {
	values := make(map[string]bool)

	for _, line := range mi.RawBody {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "return") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			val := parts[1]
			values[val] = true
		}
	}

	// Если >1 разных значений — это branching gate
	return len(values) > 1
}

// checkMultipleBranches проверяет наличие множественных веток
func (gd *GateDetector) checkMultipleBranches(mi *MethodInfo) bool {
	if mi.IfCheckCount == 0 {
		return false
	}

	// Считаем return инструкции — один проход без Join
	returnCount := 0
	for _, line := range mi.RawBody {
		if strings.Contains(line, "return") {
			returnCount++
		}
	}

	// Если >1 return — multiple branches (уже достаточно, второй подсчёт body дублировал тот же)
	if returnCount > 1 {
		return true
	}

	return false
}

// checkHasCallers проверяет есть ли callers (через CallGraph)
func (gd *GateDetector) checkHasCallers(mi *MethodInfo) bool {
	if gd.callGraph == nil {
		// Без CallGraph — предполагаем "used" (conservative)
		return true
	}

	methodID := mi.ClassName + "->" + mi.FullSignature

	// Ищем узел в графе
	node, ok := gd.callGraph.Nodes[methodID]
	if !ok {
		// Узел не найден — предполагаем что метод не используется
		return false
	}

	// Проверяем CalledBy
	return len(node.CalledBy) >= gd.minCallers
}

// calculateConfidence рассчитывает confidence анализа
func (gd *GateDetector) calculateConfidence(analysis *GateAnalysis) float64 {
	confidence := 1.0

	// Штрафы за отсутствие сигналов
	if !analysis.ReturnAffectsControlFlow {
		confidence *= 0.3
	}
	if !analysis.HasMultipleBranches {
		confidence *= 0.3
	}
	if !analysis.HasCallers {
		confidence *= 0.2
	}
	if analysis.IsDataClassMethod {
		confidence *= 0.1
	}
	if analysis.IsUtilityMethod {
		confidence *= 0.2
	}

	// Бонусы для security gates
	if analysis.GateType == GateTypeSecurityControl {
		confidence *= 1.5
		if confidence > 1.0 {
			confidence = 1.0
		}
	}

	return confidence
}

// IsGateCandidate проверяет кандидата на gate без полного анализа (быстро)
func IsGateCandidate(mi *MethodInfo) bool {
	if mi == nil {
		return false
	}

	nameLower := strings.ToLower(mi.Name)

	// Быстрый reject для очевидных non-gates
	if nameLower == "equals" ||
		nameLower == "hashcode" ||
		nameLower == "tostring" {
		return false
	}

	// Быстрый reject для геттеров
	if strings.HasPrefix(nameLower, "get") && len(mi.Name) > 3 {
		// Проверяем что после get идёт заглавная (GetName, GetValue)
		nextChar := mi.Name[3]
		if nextChar >= 'A' && nextChar <= 'Z' {
			return false
		}
	}

	// Быстрый accept для security-имён
	securityNames := []string{
		"islicensed", "ispremium", "ispro", "verify",
		"authenticate", "authorize", "check",
	}
	for _, n := range securityNames {
		if strings.Contains(nameLower, n) {
			return true
		}
	}

	// По умолчанию — требуем полный анализ
	return mi.IfCheckCount > 1 // Need at least 2 if-checks to be a candidate
}
