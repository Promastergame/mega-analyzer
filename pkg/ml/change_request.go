package ml

import (
	"fmt"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CHANGE REQUEST — явное намерение изменения.
//
// Раньше селектор извлекал желаемый исход из сигналов и добавлял +100 к
// приоритету, но Generate(mi, mode) это намерение не получал: гибкая
// стратегия заново выводила исход через ContextAnalyzer и могла вернуть
// противоположный результат. ChangeRequest несёт одно и то же намерение
// через оценку применимости, генерацию и проверку результата.
// ═══════════════════════════════════════════════════════════════════════════════

// NoTargetInstruction marks a ChangeRequest/GeneratedPatch without a
// data-selected instruction: the edit applies whole-method heuristics.
const NoTargetInstruction = -1

// EvidenceCondition — одно ветвление if-* с результатом обратного среза.
type EvidenceCondition struct {
	LineIndex      int      `json:"line_index"` // индекс в каноническом теле или -1
	Opcode         string   `json:"opcode"`
	Regs           []string `json:"regs,omitempty"`
	HasDataSupport bool     `json:"has_data_support"`
	SupportReason  string   `json:"support_reason,omitempty"`
}

// MethodEvidence — подтверждённые факты о теле метода, построенные на
// настоящем CFG/DFG (pkg/internal/cfg), а не на текстовых эвристиках.
type MethodEvidence struct {
	HasCFG       bool                `json:"has_cfg"`
	HasDFG       bool                `json:"has_dfg"`
	CFGNodes     int                 `json:"cfg_nodes,omitempty"`
	IfConditions int                 `json:"if_conditions,omitempty"`
	Conditions   []EvidenceCondition `json:"conditions,omitempty"`
	// TargetInstruction — выбранная по данным инструкция (индекс строки
	// канонического тела) или NoTargetInstruction.
	TargetInstruction int    `json:"target_instruction"`
	TargetReason      string `json:"target_reason,omitempty"`
	// InsufficientEvidence объясняет отказ, когда цель выбрать нельзя.
	InsufficientEvidence string `json:"insufficient_evidence,omitempty"`
}

// ChangeRequest — явный запрос на изменение.
type ChangeRequest struct {
	Method        *shared.MethodInfo
	Mode          PatchMode
	Desired       PatchType // конкретный ожидаемый эффект; "" = неизвестен
	DesiredReason string
	Signals       []VulnSignal
	// Conflicting — противоречащие сигналы, отложенные на разбор.
	// Порядок сигналов никогда не определяет семантику молча.
	Conflicting         []VulnSignal
	Evidence            MethodEvidence
	PreserveSideEffects bool
}

// defaultSecurityMarkers — текстовые маркеры security-источников для
// SupportReason. Это подписи свидетельств, а не выбор цели: цель выбирается
// по достижимости данных через CFG/DFG.
func defaultSecurityMarkers() []string {
	return []string{
		"root", "emulator", "debug", "tamper", "signature", "integrity",
		"hook", "xposed", "frida", "magisk", "supersu", "license", "premium",
		"billing", "payment", "auth", "biometric", "certificate", "pinning",
	}
}

// BuildChangeRequest строит единый запрос из метода, режима и сигналов.
// Два сигнала с разным желаемым исходом — конфликт: запрос возвращается без
// Desired вместе с объяснением отказа. Такой запрос нельзя генерировать,
// в том числе через legacy/fallback: конфликт требует ручного решения.
func BuildChangeRequest(mi *shared.MethodInfo, mode PatchMode, signals []VulnSignal) (*ChangeRequest, error) {
	req := &ChangeRequest{
		Method:              mi,
		Mode:                mode,
		PreserveSideEffects: true,
	}
	if err := validateChangeRequest(req); err != nil {
		return req, err
	}
	req.Evidence = BuildMethodEvidence(mi.RawBody, defaultSecurityMarkers())
	byDesired := make(map[PatchType][]VulnSignal)
	for _, s := range signals {
		pt, ok := vulnKindPatchType(s.Kind)
		if !ok {
			continue
		}
		byDesired[pt] = append(byDesired[pt], s)
	}
	if len(byDesired) == 0 {
		return req, nil
	}
	if len(byDesired) > 1 {
		desired := make([]string, 0, len(byDesired))
		for pt := range byDesired {
			desired = append(desired, string(pt))
		}
		sort.Strings(desired)
		kinds := make([]string, 0, len(desired))
		for _, pt := range desired {
			ss := byDesired[PatchType(pt)]
			kinds = append(kinds, fmt.Sprintf("%s (e.g. %s)", pt, ss[0].Kind))
			req.Conflicting = append(req.Conflicting, ss...)
		}
		return req, fmt.Errorf("conflicting signals require review, no patch intent selected: %s",
			strings.Join(kinds, " vs "))
	}
	for pt, ss := range byDesired {
		req.Desired = pt
		req.Signals = ss
		req.DesiredReason = fmt.Sprintf("signal %s requires %s", ss[0].Kind, pt)
	}
	return req, nil
}

// RequestAwareStrategy — необязательное расширение PatchStrategy.
// Стратегия, заявившая поддержку, обязана в GenerateWithRequest соблюдать
// req.Desired (при заданном) вместо собственного вывода через эвристики.
type RequestAwareStrategy interface {
	GenerateWithRequest(req *ChangeRequest) (*GeneratedPatch, error)
}

// generateWithRequest вызывает GenerateWithRequest при поддержке, иначе
// классический Generate. Поведение без запроса не меняется.
func generateWithRequest(strategy PatchStrategy, req *ChangeRequest) (*GeneratedPatch, error) {
	if err := validateChangeRequest(req); err != nil {
		return nil, err
	}
	if strategy == nil {
		return nil, fmt.Errorf("missing patch strategy")
	}
	if ra, ok := strategy.(RequestAwareStrategy); ok {
		return ra.GenerateWithRequest(req)
	}
	return strategy.Generate(req.Method, req.Mode)
}

// VerifyPatchAgainstRequest проверяет соответствие результата запросу:
// непустой патч, ожидаемый тип эффекта и тот же метод.
func VerifyPatchAgainstRequest(req *ChangeRequest, patch *GeneratedPatch) error {
	if err := validateChangeRequest(req); err != nil {
		return err
	}
	if patch == nil {
		return fmt.Errorf("nil patch")
	}
	if strings.TrimSpace(patch.PatchedCode) == "" {
		return fmt.Errorf("empty patched code")
	}
	if req.Desired != "" && patch.PatchType != req.Desired {
		return fmt.Errorf("contract mismatch: request wants %s, patch delivers %s",
			req.Desired, patch.PatchType)
	}
	if req.Method != nil && req.Method.Name != "" && patch.MethodName != "" &&
		patch.MethodName != req.Method.Name {
		return fmt.Errorf("method mismatch: request targets %s, patch is for %s",
			req.Method.Name, patch.MethodName)
	}
	if req.Method.FilePath != "" && patch.FilePath != "" &&
		patchLookupKey(req.Method.FilePath, "", "") != patchLookupKey(patch.FilePath, "", "") {
		return fmt.Errorf("file mismatch: patch targets a different source file")
	}
	wantSignature := req.Method.FullSignature
	if !strings.Contains(wantSignature, "(") {
		wantSignature = smaliCodeLine(req.Method.MethodHeader)
	}
	wantDesc := canonicalMethodDescriptor(req.Method.Name, wantSignature)
	if strings.Contains(wantSignature, "(") && patch.MethodSignature != "" &&
		canonicalMethodDescriptor(patch.MethodName, patch.MethodSignature) != wantDesc {
		return fmt.Errorf("method descriptor mismatch: request targets %s", wantDesc)
	}
	// Metadata alone is not proof: check declarations inside the generated body.
	for _, line := range strings.Split(patch.PatchedCode, "\n") {
		fields := strings.Fields(smaliCodeLine(line))
		if len(fields) < 2 || fields[0] != ".method" {
			continue
		}
		signature := fields[len(fields)-1]
		i := strings.IndexByte(signature, '(')
		if i < 0 {
			return fmt.Errorf("invalid generated method declaration")
		}
		if req.Method.Name != "" && signature[:i] != req.Method.Name {
			return fmt.Errorf("generated method name mismatch")
		}
		if strings.Contains(wantSignature, "(") && signature[i:] != wantDesc {
			return fmt.Errorf("generated method descriptor mismatch")
		}
	}
	if err := verifyReturnCoverage(req.Method.RawBody, patch.ReturnCoverage); err != nil {
		return err
	}
	return verifyMethodAccessFlags(req.Method, patch.PatchedCode)
}

// validateChangeRequest is shared by every request-aware entry point. An empty
// Desired caused by contradictory signals is NOT permission to guess an intent.
func validateChangeRequest(req *ChangeRequest) error {
	if req == nil || req.Method == nil {
		return fmt.Errorf("missing change request or method")
	}
	if reason := nonConcreteMethodReason(req.Method); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	if len(req.Conflicting) != 0 {
		return fmt.Errorf("conflicting signals require review")
	}
	return nil
}

// assessStrategyWithRequest — assessStrategy плюс:
//   - ворота RequiresCFG/RequiresDFG по свидетельствам (P1#2): стратегия,
//     объявившая требования, недопустима без подтверждённых фактов;
//   - ворота желаемого исхода (P1#1): стратегия, не производящая Desired,
//     недопустима в сигнальном пути.
func assessStrategyWithRequest(strategy PatchStrategy, req *ChangeRequest) StrategyAssessment {
	if err := validateChangeRequest(req); err != nil {
		return StrategyAssessment{Reasons: []string{err.Error()}}
	}
	a := assessStrategy(strategy, req.Method, req.Mode)
	if !a.Applicable {
		return a
	}
	if d, ok := strategy.(StrategyDescriber); ok {
		meta := d.Metadata()
		if meta.RequiresCFG && !req.Evidence.HasCFG {
			a.Applicable = false
			a.Reasons = append(a.Reasons, "requires_cfg_evidence_unavailable")
			return a
		}
		if meta.RequiresDFG && !req.Evidence.HasDFG {
			a.Applicable = false
			a.Reasons = append(a.Reasons, "requires_dfg_evidence_unavailable")
			return a
		}
	}
	if req.Desired != "" && !strategySupportsDesired(strategy, string(req.Desired)) {
		a.Applicable = false
		a.Reasons = append(a.Reasons, "desired_outcome_not_supported")
		return a
	}
	return a
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVIDENCE — факты CFG/DFG и выбор целевой инструкции по данным.
// ═══════════════════════════════════════════════════════════════════════════════

// BuildMethodEvidence строит свидетельства из тела метода: настоящий CFG,
// обратный срез регистров условий через DFGAnalyzer.Trace и выбор целевой
// инструкции. Переименование регистров, .line-директивы и перестановка
// независимых инструкций выбор не меняют: он зависит только от достижимости
// данных, а не от текстовой близости.
func BuildMethodEvidence(body []string, securityMarkers []string) MethodEvidence {
	ev := MethodEvidence{TargetInstruction: NoTargetInstruction}
	if len(body) == 0 {
		ev.InsufficientEvidence = "empty method body"
		return ev
	}
	code := strings.Join(body, "\n")
	graph := buildPreflightCFG(code)
	if graph == nil || len(graph.Nodes) == 0 {
		ev.InsufficientEvidence = "CFG unavailable for method body"
		return ev
	}
	ev.HasCFG = true
	ev.CFGNodes = len(graph.Nodes)
	analyzer := cfg.NewDFGAnalyzer(graph)
	analyzer.Analyze()
	ev.HasDFG = true

	lines := strings.Split(canonicalPatchText(code), "\n")
	claimed := make([]bool, len(lines))
	if graph.Method == nil {
		ev.InsufficientEvidence = "CFG has no method instructions"
		return ev
	}
	for _, instr := range graph.Method.Instructions {
		if instr == nil || !strings.HasPrefix(instr.Opcode, "if-") {
			continue
		}
		cond := EvidenceCondition{
			LineIndex: matchEvidenceLine(lines, claimed, instr),
			Opcode:    instr.Opcode,
			Regs:      append([]string{}, instr.UseRegs...),
		}
		for _, reg := range instr.UseRegs {
			if reason, ok := traceExternalSupport(analyzer, instr, reg, securityMarkers); ok {
				cond.HasDataSupport = true
				cond.SupportReason = reason
				break
			}
		}
		ev.Conditions = append(ev.Conditions, cond)
	}
	ev.IfConditions = len(ev.Conditions)

	var supported []int
	for i := range ev.Conditions {
		if ev.Conditions[i].HasDataSupport && ev.Conditions[i].LineIndex >= 0 {
			supported = append(supported, i)
		}
	}
	switch len(supported) {
	case 0:
		ev.InsufficientEvidence = "no data-supported branch condition"
	case 1:
		ev.TargetInstruction = ev.Conditions[supported[0]].LineIndex
		ev.TargetReason = ev.Conditions[supported[0]].SupportReason
	default:
		ev.InsufficientEvidence = fmt.Sprintf(
			"ambiguous target: %d data-supported conditions, refusing to guess", len(supported))
	}
	return ev
}

// matchEvidenceLine связывает инструкцию CFG со строкой канонического тела.
// Основной путь — поле Line (1-based); запасной — текстовое совпадение Raw.
func matchEvidenceLine(lines []string, claimed []bool, instr *cfg.Instruction) int {
	if instr.Line >= 1 && instr.Line <= len(lines) &&
		!claimed[instr.Line-1] &&
		strings.TrimSpace(lines[instr.Line-1]) == strings.TrimSpace(instr.Raw) {
		claimed[instr.Line-1] = true
		return instr.Line - 1
	}
	want := strings.TrimSpace(instr.Raw)
	if want == "" {
		return -1
	}
	for i, line := range lines {
		if !claimed[i] && strings.TrimSpace(line) == want {
			claimed[i] = true
			return i
		}
	}
	return -1
}

// traceExternalSupport проверяет, что регистр условия достижим из внешнего
// источника (invoke, const-string, чтение поля/массива), а не из локальной
// константы. Возвращает причину поддержки для отчётности.
func traceExternalSupport(analyzer *cfg.DFGAnalyzer, instr *cfg.Instruction, reg string, securityMarkers []string) (string, bool) {
	if analyzer == nil {
		return "", false
	}
	for _, step := range analyzer.Trace(reg, instr, 8) {
		src := step.Instruction
		if src == nil {
			continue
		}
		if !isExternalSourceOpcode(src.Opcode, src.InvokeRef != "") {
			continue
		}
		what := src.Opcode
		if src.InvokeRef != "" {
			what = src.InvokeRef
		} else if src.ConstVal != nil && *src.ConstVal != "" {
			what = *src.ConstVal
		}
		if hit := matchSecurityMarker(what, securityMarkers); hit != "" {
			return fmt.Sprintf("condition reg %s flows from security source %s", reg, hit), true
		}
		return fmt.Sprintf("condition reg %s flows from external %s", reg, src.Opcode), true
	}
	return "", false
}

// isExternalSourceOpcode — значение приходит извне локальных констант:
// вызов, move-result вызова, строковая константа, чтение поля/массива,
// создание объекта. Локальные const/4 и move между регистрами — нет.
func isExternalSourceOpcode(opcode string, hasInvokeRef bool) bool {
	switch {
	case strings.HasPrefix(opcode, "invoke-"):
		return true
	case strings.HasPrefix(opcode, "move-result"):
		return hasInvokeRef
	case strings.HasPrefix(opcode, "const-string"):
		return true
	case strings.HasPrefix(opcode, "iget"),
		strings.HasPrefix(opcode, "sget"),
		strings.HasPrefix(opcode, "aget"):
		return true
	case strings.HasPrefix(opcode, "new-"),
		strings.HasPrefix(opcode, "check-cast"):
		return true
	}
	return false
}

func matchSecurityMarker(what string, markers []string) string {
	lower := strings.ToLower(what)
	for _, m := range markers {
		if m != "" && strings.Contains(lower, strings.ToLower(m)) {
			return m
		}
	}
	return ""
}

// isProbableNullCheck — консервативная эвристика: if-eqz/if-nez над
// регистром, чьи достижимые определения объектные (move-result-object,
// check-cast, new-instance, iget-object/sget-object/aget-object). Целочисленный
// ноль от const/4 так не помечается: его нельзя отличить, и молча инвертировать
// его опаснее, чем пропустить. Используется только чтобы НЕ трогать
// технические проверки; выбор цели всегда идёт через Evidence.
func isProbableNullCheck(body []string, lineIdx int, reg string) bool {
	if reg == "" || lineIdx < 0 || lineIdx >= len(body) {
		return false
	}
	for i := lineIdx - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(body[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, ":") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		if definesRegister(fields[0], fields, reg) {
			op := fields[0]
			return op == "move-result-object" || op == "check-cast" ||
				op == "new-instance" ||
				op == "iget-object" || op == "sget-object" || op == "aget-object"
		}
	}
	return false
}

// definesRegister — инструкция с опкодом fields[0] определяет reg.
// Покрывает const/move (dst первый), invoke-результаты (следующая строка —
// дело вызывающего кода, здесь только прямые формы), iput/sput/aput нет
// (не определяют регистр), monitor/return/if/goto/invoke — нет.
func definesRegister(opcode string, fields []string, reg string) bool {
	if len(fields) < 2 {
		return false
	}
	dst := strings.TrimSuffix(fields[1], ",")
	if dst != reg {
		return false
	}
	switch {
	case strings.HasPrefix(opcode, "const"),
		strings.HasPrefix(opcode, "move-result"),
		opcode == "move" || strings.HasPrefix(opcode, "move/"),
		strings.HasPrefix(opcode, "move-object"),
		strings.HasPrefix(opcode, "move-wide"),
		strings.HasPrefix(opcode, "iget"),
		strings.HasPrefix(opcode, "sget"),
		strings.HasPrefix(opcode, "aget"),
		strings.HasPrefix(opcode, "array-length"),
		strings.HasPrefix(opcode, "new-"),
		strings.HasPrefix(opcode, "check-cast"),
		strings.HasPrefix(opcode, "instance-of"),
		strings.HasPrefix(opcode, "add-"),
		strings.HasPrefix(opcode, "sub-"),
		strings.HasPrefix(opcode, "mul-"),
		strings.HasPrefix(opcode, "div-"),
		strings.HasPrefix(opcode, "rem-"),
		strings.HasPrefix(opcode, "and-"),
		strings.HasPrefix(opcode, "or-"),
		strings.HasPrefix(opcode, "xor-"),
		strings.HasPrefix(opcode, "shl-"),
		strings.HasPrefix(opcode, "shr-"),
		strings.HasPrefix(opcode, "ushr-"),
		strings.HasPrefix(opcode, "neg-"),
		strings.HasPrefix(opcode, "not-"),
		strings.HasPrefix(opcode, "cmp"):
		return true
	}
	return false
}

// targetConditionLine возвращает строку целевой инструкции из Evidence
// (каноническое тело) или NoTargetInstruction.
func targetConditionLine(ev *MethodEvidence) int {
	if ev == nil {
		return NoTargetInstruction
	}
	return ev.TargetInstruction
}
