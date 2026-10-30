package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OBJECT RETURN INJECTION — хирургический возврат для объектов
//
// Половина license/token геттеров возвращает ОБЪЕКТЫ:
//   isPremium()Ljava/lang/Boolean;  getToken()Ljava/lang/String;
//   getItems()Ljava/util/List;
//
// Раньше их мог патчить только whole-body стаб. Теперь:
//   (a) sget-object swap: Boolean.FALSE → Boolean.TRUE (тот же размер 2u!)
//   (b) const-string swap: любая строка → "" (тот же размер, string pool)
//   (c) branchless insert перед return-object (sget/const-string/invoke+move)
//   (d) при branches/hazard — только swap, иначе валидный стаб
//
// Приоритет 87 — рядом с cooldown (87), ниже price (89): объекты реже
// однозначны, чем цена/баланс.
// ═══════════════════════════════════════════════════════════════════════════════

// ObjectReturnInjectionStrategy форсит объектный возврат хирургически.
type ObjectReturnInjectionStrategy struct {
	priority int
}

// NewObjectReturnInjectionStrategy создаёт стратегию.
func NewObjectReturnInjectionStrategy() *ObjectReturnInjectionStrategy {
	return &ObjectReturnInjectionStrategy{priority: 87}
}

// objectGateTokens — имена объектных гейтов (лицензия/токен/доступ).
// Без именного гейта стратегия хватала любые String-методы: SHA1,
// getDeviceId, doInBackground — нейтральные утилиты, а не проверки,
// и нейтрализовала их пустой строкой/null под видом return_true.
var objectGateTokens = []string{
	"token", "auth", "session", "secret", "password", "credential",
	"license", "licence", "premium", "entitle", "subscription",
	"apikey", "api_key", "login", "ticket", "permission",
	"purchase", "receipt",
}

// isObjectGateName reports whether the (already lower-cased) method name
// looks like an object-returning access/license gate.
func isObjectGateName(nameLower string) bool {
	if nameLower == "" {
		return false
	}
	for _, tok := range objectGateTokens {
		if strings.Contains(nameLower, tok) {
			return true
		}
	}
	return false
}

// hasSwappableObjectConst reports whether a return-object site has an
// immediately preceding executable const-string or boxed-Boolean-FALSE
// definition for the same register — i.e. Tier-1 can do a size-neutral swap
// without falling back to a whole-body stub. This admits obfuscated
// single-letter gates ("v", "ik") whose names carry no signal but whose
// returned root-indicator strings are legitimate bypass targets, while
// still declining neutral utilities (SHA1, getDeviceId) that have nothing
// to swap and would otherwise be neutered by a stub.
func hasSwappableObjectConst(body []string) bool {
	predecessors := straightLinePredecessors(body)
	for i, raw := range body {
		fields := strings.Fields(smaliCodeLine(raw))
		if len(fields) != 2 || fields[0] != "return-object" {
			continue
		}
		j := predecessors[i]
		if j < 0 {
			continue
		}
		trimmed := smaliCodeLine(body[j])
		defFields := strings.Fields(trimmed)
		if len(defFields) < 2 {
			continue
		}
		dst := strings.TrimSuffix(defFields[1], ",")
		if dst != fields[1] {
			continue
		}
		if defFields[0] == "const-string" || defFields[0] == "const-string/jumbo" {
			return true
		}
		if defFields[0] == "sget-object" && strings.HasSuffix(trimmed, "Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;") {
			return true
		}
	}
	return false
}

// CanApply: research, объектный возврат (L или [), есть return-object,
// плюс именной гейт ИЛИ непосредственно свопаемая объектная константа.
func (s *ObjectReturnInjectionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	if mode != PatchModeResearch {
		return false
	}
	name := mi.NameLower
	if name == "" {
		name = strings.ToLower(mi.Name)
	}
	if !isObjectGateName(name) && !hasSwappableObjectConst(mi.RawBody) {
		return false
	}
	rt := strings.TrimSpace(mi.ReturnType)
	if rt == "" {
		// пробуем вывести из сигнатуры
		if idx := strings.LastIndex(mi.FullSignature, ")"); idx >= 0 && idx+1 < len(mi.FullSignature) {
			rt = mi.FullSignature[idx+1:]
		}
	}
	if !strings.HasPrefix(rt, "L") && !strings.HasPrefix(rt, "[") {
		return false
	}
	return hasReturnObject(mi.RawBody)
}

// Generate форсит объектный возврат.
func (s *ObjectReturnInjectionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	rt := strings.TrimSpace(mi.ReturnType)
	if rt == "" {
		rt = effectiveReturnType("", mi.FullSignature, mi.MethodHeader)
	}
	smaliCode, count, note := overrideObjectReturnsSafe(mi.RawBody, rt)
	if count == 0 {
		header := mi.MethodHeader
		if header == "" {
			header = shared.ReconstructStubHeader(mi)
		}
		smaliCode = buildStubMethodSmart(header, mi.FullSignature, rt, kindTrue)
		count = 1
		note = "surgical object override refused layout; emitted validated stub"
	}
	desc := fmt.Sprintf("Force object getter %s (%s) at %d return-object site(s)", mi.Name, rt, count)
	if note != "" {
		desc += "; " + note
	}
	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    PatchReturnTrue,
		Description:  desc,
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation: PatchExplanation{
			Reason:       fmt.Sprintf("%s returns object %s (token/list/boxed).", mi.Name, rt),
			WhatItDoes:   "Swaps Boolean FALSE→TRUE / strings→empty / collections→empty in place; inserts only in branchless methods.",
			WhyThisPatch: "Object stubs via whole-body rewrite drop side effects; surgical keeps telemetry while neutralising the value.",
			Impact:       "Callers receive a benign authorized/empty value instead of a live token.",
			Signals:      []string{fmt.Sprintf("Object getter: %s:%s", mi.Name, rt)},
		},
	}
	patch.ReturnCoverage = returnSiteCoverage(mi.RawBody, "return-object", count)
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *ObjectReturnInjectionStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *ObjectReturnInjectionStrategy) PatchType() PatchType { return PatchReturnTrue }

// GetDescription returns a human-readable description.
func (s *ObjectReturnInjectionStrategy) GetDescription() string {
	return "Surgically force object getters (Boolean/String/List) to benign values before each return-object; stub fallback when layout is unsafe."
}

func (s *ObjectReturnInjectionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "object_return_injection",
		SupportedRoles:       []MethodRole{MethodRoleValueProvider, MethodRoleBooleanGate},
		PreservesControlFlow: true,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func hasReturnObject(body []string) bool {
	for _, line := range body {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 2 && fields[0] == "return-object" {
			return true
		}
	}
	return false
}

// overrideObjectReturnsSafe — хирургический override return-object.
// Swap-first (size-neutral), insert-only-branchless, иначе note.
func overrideObjectReturnsSafe(body []string, returnType string) (string, int, string) {
	sites := []int{}
	for i, line := range body {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 2 && fields[0] == "return-object" {
			sites = append(sites, i)
		}
	}
	if len(sites) == 0 {
		return strings.Join(body, "\n") + "\n", 0, ""
	}
	// Tier 1: size-neutral swaps (sget Boolean FALSE→TRUE, const-string → "").
	out := make([]string, len(body))
	copy(out, body)
	swapped := map[int]bool{}
	predecessors := straightLinePredecessors(body)
	for _, si := range sites {
		reg := objectReturnReg(body[si])
		j := predecessors[si]
		if j < 0 {
			continue
		}
		if newLine, ok := tryObjectSwap(body[j], reg, returnType); ok {
			out[j] = newLine
			swapped[si] = true
		}
	}
	remaining := []int{}
	for _, si := range sites {
		if !swapped[si] {
			remaining = append(remaining, si)
		}
	}
	if len(remaining) == 0 {
		return strings.Join(out, "\n") + "\n", len(sites), ""
	}
	if hasRelayoutHazard(out) || hasNumericBranch(out) {
		note := fmt.Sprintf("%d object return site(s) left unforced: branches/hazard need relayout", len(remaining))
		return strings.Join(out, "\n") + "\n", len(sites) - len(remaining), note
	}
	// Branchless insert.
	remainSet := map[int]bool{}
	for _, si := range remaining {
		remainSet[si] = true
	}
	var b strings.Builder
	forced := len(sites) - len(remaining)
	for i, line := range out {
		if remainSet[i] {
			reg := objectReturnReg(line)
			indent := indentLike(line)
			for _, ins := range objectForcingLines(reg, returnType) {
				b.WriteString(indent + ins + "\n")
			}
			forced++
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), forced, ""
}

func objectReturnReg(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 2 {
		return fields[1]
	}
	return "v0"
}

// tryObjectSwap пробует size-neutral замену дефа регистра.
func tryObjectSwap(defLine, reg, returnType string) (string, bool) {
	indent := indentLike(defLine)
	trimmed := smaliCodeLine(defLine)
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return "", false
	}
	dst := strings.TrimSuffix(fields[1], ",")
	if dst != reg {
		return "", false
	}
	// Boolean FALSE → TRUE (sget-object, тот же размер)
	if returnType == "Ljava/lang/Boolean;" && fields[0] == "sget-object" && strings.HasSuffix(trimmed, "Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;") {
		return indent + strings.Replace(trimmed, "Ljava/lang/Boolean;->FALSE", "Ljava/lang/Boolean;->TRUE", 1), true
	}
	// Любая const-string на тот же регистр → "" (тот же размер 2u)
	if (returnType == "Ljava/lang/String;" || returnType == "Ljava/lang/CharSequence;") &&
		(fields[0] == "const-string" || fields[0] == "const-string/jumbo") {
		return fmt.Sprintf("%s%s %s, \"\"", indent, fields[0], reg), true
	}
	return "", false
}

// objectForcingLines возвращает инструкции для форса объекта (branchless insert).
func objectForcingLines(reg, returnType string) []string {
	switch returnType {
	case "Ljava/lang/Boolean;":
		return []string{fmt.Sprintf("sget-object %s, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;", reg)}
	case "Ljava/lang/String;", "Ljava/lang/CharSequence;":
		return []string{fmt.Sprintf("const-string %s, \"\"", reg)}
	case "Ljava/util/List;", "Ljava/util/Collection;", "Ljava/lang/Iterable;":
		return []string{
			"invoke-static {}, Ljava/util/Collections;->emptyList()Ljava/util/List;",
			fmt.Sprintf("move-result-object %s", reg),
		}
	case "Ljava/util/Set;":
		return []string{
			"invoke-static {}, Ljava/util/Collections;->emptySet()Ljava/util/Set;",
			fmt.Sprintf("move-result-object %s", reg),
		}
	case "Ljava/util/Map;":
		return []string{
			"invoke-static {}, Ljava/util/Collections;->emptyMap()Ljava/util/Map;",
			fmt.Sprintf("move-result-object %s", reg),
		}
	default:
		// Безопасный null для прочих объектов/массивов.
		// NOTE: insert 1u const/4 — для branchless без hazard это безопасно
		// (hasNumericBranch==false проверен вызывателем).
		return []string{fmt.Sprintf("const/4 %s, 0x0", reg)}
	}
}
