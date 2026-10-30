package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH GENERATOR — генерирует готовые патчи для --show-fix
//
// Умеет:
//   - Генерировать патч для каждого типа (return true/false/void/int)
//   - Форматировать diff (original → patched)
//   - Определять минимальные registers
//   - Сохранять .method header корректным
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════

// PatchGenerator генерирует патчи
type PatchGenerator struct {
	maxOriginalLines int
	contextAnalyzer  *ContextAnalyzer
	strategySelector *StrategySelector
	validator        *SmaliValidator
	mode             PatchMode     // operational mode: defensive or research
	smartPatcher     *SmartPatcher // умный анализ для реальных патчей
}

// NewPatchGenerator создаёт генератор
func NewPatchGenerator() *PatchGenerator {
	ca := NewContextAnalyzer()
	return &PatchGenerator{
		maxOriginalLines: 40,
		contextAnalyzer:  ca,
		strategySelector: NewStrategySelectorWithAnalyzer(ca),
		validator:        NewSmaliValidator(),
		mode:             "", // Mode must be set explicitly via SetMode
		smartPatcher:     NewSmartPatcher(),
	}
}

// SetMode sets the operational mode for patch generation
// Requirements: 3.1, 3.2
func (pg *PatchGenerator) SetMode(mode PatchMode) {
	pg.mode = mode
}

// GetMode returns the current operational mode
// Requirements: 3.1, 3.2
func (pg *PatchGenerator) GetMode() PatchMode {
	return pg.mode
}

// ═══════════════════════════════════════════════════════════════════════════════
// GENERATE — главная функция
// ═══════════════════════════════════════════════════════════════════════════════

// Generate создаёт патч для PatchPoint
func (pg *PatchGenerator) Generate(point *PatchPoint) *GeneratedPatch {
	if point == nil {
		return nil
	}
	if reason := nonConcreteMethodReason(pg.patchPointToMethodInfo(point)); reason != "" {
		return nil
	}
	pg.normalizePatchPoint(point)
	if pg.mode != "" {
		return pg.GenerateWithMode(point, pg.mode)
	}
	// The legacy API is retained, but contradictory signals are never ignored.
	if point != nil && point.VulnSignals != nil {
		if _, err := BuildChangeRequest(pg.patchPointToMethodInfo(point), pg.mode, point.VulnSignals.Signals); err != nil {
			return nil
		}
	}
	return pg.generateLegacy(point)
}

// normalizePatchPoint заполняет ReturnType из сигнатуры/header и подбирает
// SuggestedPatch, если скорер его не задал (раньше всегда ставился return_void).
func (pg *PatchGenerator) normalizePatchPoint(point *PatchPoint) {
	if point == nil {
		return
	}
	point.ReturnType = effectiveReturnType(point.ReturnType, point.MethodSignature, point.MethodHeader)
	if point.SuggestedPatch == "" {
		point.SuggestedPatch = suggestPatchTypeForReturn(point.ReturnType, point.MethodName)
	}
}

func (pg *PatchGenerator) generateLegacy(point *PatchPoint) *GeneratedPatch {
	if point == nil || len(point.MethodBody) == 0 {
		return pg.generateFromSignature(point)
	}

	var smartPatch *SmartPatch
	if pg.smartPatcher != nil {
		smartPatches := pg.smartPatcher.AnalyzeMethod(point)
		if len(smartPatches) > 0 {
			bestPatch := smartPatches[0]
			for i := range smartPatches {
				if smartPatches[i].Confidence > bestPatch.Confidence {
					bestPatch = smartPatches[i]
				}
			}
			if bestPatch.Confidence >= 0.75 {
				smartPatch = &bestPatch
			}
		}
	}

	if smartPatch != nil {
		if patch := pg.generateSmartPatch(point, smartPatch); patch != nil {
			return patch
		}
	}

	patch := &GeneratedPatch{
		PatchType:       point.SuggestedPatch,
		MethodName:      point.MethodName,
		MethodSignature: point.MethodSignature,
		FilePath:        point.FilePath,
	}

	if tmpl, ok := GetPatchTemplate(point.SuggestedPatch); ok {
		patch.Description = tmpl.Description
	}

	patch.OriginalCode = pg.buildOriginalCode(point)
	patch.OriginalLines = len(point.MethodBody)

	patch.PatchedCode = pg.buildPatchedCode(point)
	patch.PatchedLines = countLines(patch.PatchedCode)

	validationResult := pg.validator.ValidateStrict(patch.PatchedCode)

	patch.DiffView = buildDiffView(patch)
	patch.OriginalBlock = buildMarkdownBlock(patch.OriginalCode, "smali")
	patch.PatchedBlock = buildMarkdownBlock(patch.PatchedCode, "smali")

	checkType := pg.contextAnalyzer.DetermineCheckType(pg.patchPointToMethodInfo(point))
	patch.Explanation = buildExplanation(point, checkType, pg.mode)
	patch.Confidence = point.Confidence
	patch.ConfidenceBreakdown = point.ConfidenceBreakdown
	patch.RuntimeConfidence = point.RuntimeConfidence
	patch.RuntimeDecision = point.RuntimeDecision
	patch.Artifact = buildArtifact(point, patch, validationResult)

	return patch
}

// GenerateWithMode creates a patch using the unified planner (P2#6):
// one BuildChangeRequest → PlanPatch pass (candidates → generate →
// request-contract → structural validation → select). Conflicting signals or
// exhausted candidates fail closed. Legacy generation must not override a
// planner rejection with a different intent or an unchecked template.
func (pg *PatchGenerator) GenerateWithMode(point *PatchPoint, mode PatchMode) *GeneratedPatch {
	if point == nil {
		return nil
	}
	pg.normalizePatchPoint(point)

	mi := pg.patchPointToMethodInfo(point)
	var signals []VulnSignal
	if point.VulnSignals != nil {
		signals = point.VulnSignals.Signals
	}
	req, reqErr := BuildChangeRequest(mi, mode, signals)
	if reqErr != nil {
		return nil
	}
	planned := pg.strategySelector.PlanPatch(req)
	if planned == nil || planned.Patch == nil {
		return nil
	}

	patch := planned.Patch
	patch.FilePath = point.FilePath
	patch.MethodName = point.MethodName
	patch.MethodSignature = point.MethodSignature

	patch.Confidence = point.Confidence
	patch.ConfidenceBreakdown = point.ConfidenceBreakdown
	patch.RuntimeConfidence = point.RuntimeConfidence
	patch.RuntimeDecision = point.RuntimeDecision
	patch.Mode = mode
	if planned.IsPartial && patch.RuntimeDecision != "reject" {
		patch.RuntimeDecision = "needs_review"
	}

	if patch.DiffView == "" {
		patch.DiffView = buildDiffView(patch)
	}
	patch.OriginalBlock = buildMarkdownBlock(patch.OriginalCode, "smali")
	patch.PatchedBlock = buildMarkdownBlock(patch.PatchedCode, "smali")
	validationResult := pg.validator.ValidateStrict(patch.PatchedCode)
	if !validationResult.Valid {
		// Never replace a rejected candidate with an unverified fallback stub.
		return nil
	}
	patch.Artifact = buildArtifact(point, patch, validationResult)
	if !patch.Artifact.Validation.Valid {
		return nil
	}

	return patch
}

// buildFallbackStub — используется, когда стратегия выдала невалидный smali.
// Сначала пытаемся СОХРАНИТЬ тело (ранний return-void / offset-safe подмена
// значения), и только при отсутствии тела падаем в полноразмерную заглушку.
func (pg *PatchGenerator) buildFallbackStub(point *PatchPoint) string {
	header := point.MethodHeader
	if header == "" && len(point.MethodBody) > 0 {
		header = point.MethodBody[0]
	}
	if header == "" {
		header = fmt.Sprintf(".method public %s%s", point.MethodName, pg.extractMethodDesc(point.MethodSignature))
	}

	rt := effectiveReturnType(point.ReturnType, point.MethodSignature, point.MethodHeader)
	kind := patchKindFor(point.SuggestedPatch)
	if point.SuggestedPatch == PatchRemoveCheck {
		kind = kindTrue
		if rt == "V" {
			kind = kindVoid
		}
	}

	if preserved, ok := buildBodyPreservingPatch(point.MethodBody, rt, kind); ok {
		return preserved
	}

	return buildStubMethodSmart(header, point.MethodSignature, rt, kind)
}

// patchPointToMethodInfo converts a PatchPoint to shared.MethodInfo
func (pg *PatchGenerator) patchPointToMethodInfo(point *PatchPoint) *shared.MethodInfo {
	returnCount, ifCount, secCalls, secStrings, regCount, hasLocals := summarizeMethodBodyForStrategy(point.MethodBody)
	mi := &shared.MethodInfo{
		Economy:            point.Economy,
		Name:               point.MethodName,
		NameLower:          strings.ToLower(point.MethodName),
		ClassName:          point.ClassName,
		FilePath:           point.FilePath,
		FullSignature:      point.MethodSignature,
		ReturnType:         point.ReturnType,
		ReturnsBoolean:     point.ReturnType == "Z",
		ReturnsVoid:        point.ReturnType == "V",
		ReturnsInt:         point.ReturnType == "I",
		IsAppCode:          point.IsAppCode,
		RawBody:            point.MethodBody,
		MethodHeader:       point.MethodHeader,
		InstructionCount:   len(point.MethodBody),
		ReturnCount:        returnCount,
		IfCheckCount:       ifCount,
		RegisterCount:      regCount,
		HasLocalsDirective: hasLocals,
		HasDualReturn:      hasDualReturnShapes(point.MethodBody),
		SecurityCalls:      secCalls,
		SecurityStrings:    secStrings,
		HasSecurityAPI:     len(secCalls) > 0,
		HasSecurityStrings: len(secStrings) > 0,
	}

	// Parse method header for additional flags
	if point.MethodHeader != "" {
		header := strings.ToLower(point.MethodHeader)
		mi.IsPublic = strings.Contains(header, " public ")
		mi.IsPrivate = strings.Contains(header, " private ")
		mi.IsStatic = strings.Contains(header, " static ")
		mi.IsFinal = strings.Contains(header, " final ")
	}

	return mi
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD ORIGINAL CODE
// ═══════════════════════════════════════════════════════════════════════════════

func (pg *PatchGenerator) buildOriginalCode(point *PatchPoint) string {
	var b strings.Builder

	lines := point.MethodBody
	if len(lines) > pg.maxOriginalLines {
		// Показываем начало и конец
		halfShow := pg.maxOriginalLines / 2
		for i := 0; i < halfShow; i++ {
			b.WriteString(lines[i])
			b.WriteByte('\n')
		}
		b.WriteString(fmt.Sprintf("    # ... (%d lines omitted) ...\n", len(lines)-pg.maxOriginalLines))
		for i := len(lines) - halfShow; i < len(lines); i++ {
			b.WriteString(lines[i])
			b.WriteByte('\n')
		}
	} else {
		for _, line := range lines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD PATCHED CODE
// ═══════════════════════════════════════════════════════════════════════════════

func (pg *PatchGenerator) buildPatchedCode(point *PatchPoint) string {
	// SMART BUILDER: регистро-корректный `.locals` + семантические возвраты.
	// См. patch_smali_builder.go (P1..P4). Заменяет прежнюю ручную сборку с
	// фиксированным `.registers` и null-возвратами объектов.
	header := point.MethodHeader
	if header == "" && len(point.MethodBody) > 0 {
		header = point.MethodBody[0]
	}

	rt := effectiveReturnType(point.ReturnType, point.MethodSignature, point.MethodHeader)

	kind := patchKindFor(point.SuggestedPatch)
	if point.SuggestedPatch == PatchRemoveCheck {
		// remove_check сохраняет семантику success-ветки: для void — return-void,
		// иначе — «успешное» значение нужного типа.
		kind = kindTrue
		if rt == "V" {
			kind = kindVoid
		}
	}

	// BODY-PRESERVING FIRST. Пока у нас есть реальное тело метода, мы его НЕ
	// выбрасываем: void глушим ранним `return-void`, примитивный возврат
	// подменяем на месте через offset-safe движок, а объектные/wide/несогласо-
	// ванные случаи оставляем как есть. Это и есть «патчить что-то, а не
	// ПОЛНОСТЬЮ удалять». Полноразмерная заглушка ниже — резерв для точек, у
	// которых тела нет (только сигнатура).
	if preserved, ok := buildBodyPreservingPatch(point.MethodBody, rt, kind); ok {
		return preserved
	}

	return buildStubMethodSmart(header, point.MethodSignature, rt, kind)
}

func (pg *PatchGenerator) buildRemoveCheckPatch(b *strings.Builder, point *PatchPoint) {
	switch point.ReturnType {
	case "Z":
		b.WriteString("    const/4 v0, 0x1\n")
		b.WriteString("    return v0\n")
	case "V":
		b.WriteString("    return-void\n")
	default:
		pg.writeDefaultReturn(b, point)
	}
}

func (pg *PatchGenerator) writeDefaultReturn(b *strings.Builder, point *PatchPoint) {
	switch point.ReturnType {
	case "V":
		b.WriteString("    return-void\n")
	case "J", "D":
		b.WriteString("    const-wide/16 v0, 0x0\n")
		b.WriteString("    return-wide v0\n")
	case "L", "[":
		b.WriteString("    const/4 v0, 0x0\n")
		b.WriteString("    return-object v0\n")
	case "I", "S", "B", "C":
		b.WriteString("    # Return max int (0x7FFFFFFF = 2147483647)\n")
		b.WriteString("    const v0, 0x7fffffff\n")
		b.WriteString("    return v0\n")
	case "F":
		b.WriteString("    const/4 v0, 0x0\n")
		b.WriteString("    return v0\n")
	default:
		if strings.HasPrefix(point.ReturnType, "L") || strings.HasPrefix(point.ReturnType, "[") {
			b.WriteString("    const/4 v0, 0x0\n")
			b.WriteString("    return-object v0\n")
			return
		}
		b.WriteString("    const/4 v0, 0x0\n")
		b.WriteString("    return v0\n")
	}
}

// getRequiredRegisters определяет минимум регистров для патча
func (pg *PatchGenerator) getRequiredRegisters(point *PatchPoint) int {
	switch point.SuggestedPatch {
	case PatchReturnVoid, PatchNop:
		// void не нужны регистры, но нужен p0 для instance methods
		if isStaticMethod(point.MethodHeader) {
			return 0
		}
		return 1

	case PatchReturnTrue, PatchReturnFalse:
		if isStaticMethod(point.MethodHeader) {
			return 1 // только v0
		}
		return 2 // p0 + v0

	case PatchReturnMaxInt:
		if isStaticMethod(point.MethodHeader) {
			return 1
		}
		return 2

	default:
		return 2
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD DIFF VIEW
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// MARKDOWN BLOCK
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// GENERATE FROM SIGNATURE (когда нет body)
// ═══════════════════════════════════════════════════════════════════════════════

func (pg *PatchGenerator) generateFromSignature(point *PatchPoint) *GeneratedPatch {
	if point == nil {
		return nil
	}

	patch := &GeneratedPatch{
		PatchType:       point.SuggestedPatch,
		MethodName:      point.MethodName,
		MethodSignature: point.MethodSignature,
		FilePath:        point.FilePath,
	}

	if tmpl, ok := GetPatchTemplate(point.SuggestedPatch); ok {
		patch.Description = tmpl.Description
	}

	// Генерируем без оригинального кода
	header := point.MethodHeader
	if header == "" {
		// Восстанавливаем header из данных
		access := "public"
		if !point.IsAppCode {
			access = "private"
		}
		header = fmt.Sprintf(".method %s %s(%s)%s",
			access, point.MethodName, "", point.ReturnType)
	}

	patch.OriginalCode = header + "\n    # (original code not available)\n.end method"
	patch.OriginalLines = 3

	// SMART BUILDER: корректные регистры (.locals) и семантические возвраты
	// нужного типа вместо фиксированного `.registers`/null. См. patch_smali_builder.go.
	patch.PatchedCode = buildStubMethodSmart(header, point.MethodSignature, point.ReturnType,
		patchKindFor(point.SuggestedPatch))
	patch.PatchedLines = countLines(patch.PatchedCode)

	patch.DiffView = buildDiffView(patch)
	patch.OriginalBlock = buildMarkdownBlock(patch.OriginalCode, "smali")
	patch.PatchedBlock = buildMarkdownBlock(patch.PatchedCode, "smali")

	// Context analysis and explanation (Requirements 6.5, 6.6, 6.7)
	checkType := pg.contextAnalyzer.DetermineCheckType(pg.patchPointToMethodInfo(point))
	patch.Explanation = buildExplanation(point, checkType, pg.mode)
	patch.Confidence = point.Confidence
	patch.ConfidenceBreakdown = point.ConfidenceBreakdown

	validationResult := pg.validator.ValidateStrict(patch.PatchedCode)
	patch.Artifact = buildArtifact(point, patch, validationResult)

	return patch
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMART PATCH GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// generateSmartPatch создает патч на основе анализа SmartPatcher
func (pg *PatchGenerator) generateSmartPatch(point *PatchPoint, smartPatch *SmartPatch) *GeneratedPatch {
	patch := &GeneratedPatch{
		MethodName:      point.MethodName,
		MethodSignature: point.MethodSignature,
		FilePath:        point.FilePath,
	}

	// Определяем тип патча из стратегии
	switch smartPatch.Strategy.Type {
	case "return_true":
		patch.PatchType = PatchReturnTrue
		patch.Description = smartPatch.Target.TargetName() + " - Force return true"
	case "return_false":
		patch.PatchType = PatchReturnFalse
		patch.Description = smartPatch.Target.TargetName() + " - Force return false"
	case "return_void":
		patch.PatchType = PatchReturnVoid
		patch.Description = smartPatch.Target.TargetName() + " - Force return void"
	case "const_replace":
		patch.PatchType = PatchConstReplace
		patch.Description = smartPatch.Target.TargetName() + " - Replace constant: " + smartPatch.OriginalURL
	default:
		patch.PatchType = point.SuggestedPatch
		patch.Description = smartPatch.Explanation
	}

	// Оригинальный код
	patch.OriginalCode = pg.buildOriginalCode(point)
	patch.OriginalLines = len(point.MethodBody)

	// Патченый код на основе стратегии
	patch.PatchedCode = pg.buildSmartPatchedCode(point, smartPatch)
	if patch.PatchedCode == "" {
		return nil
	}
	patch.PatchedLines = countLines(patch.PatchedCode)

	// Diff view
	patch.DiffView = buildDiffView(patch)

	// Markdown blocks
	patch.OriginalBlock = buildMarkdownBlock(patch.OriginalCode, "smali")
	patch.PatchedBlock = buildMarkdownBlock(patch.PatchedCode, "smali")

	// Explanation от SmartPatcher
	patch.Explanation = PatchExplanation{
		Reason:       smartPatch.Explanation,
		WhatItDoes:   "Original: " + smartPatch.Target.TargetName(),
		WhyThisPatch: "Strategy: " + smartPatch.Strategy.Type,
		Impact:       "Bypass/replace detected security check",
		Signals:      buildSignalsList(point),
	}

	validationResult := pg.validator.ValidateStrict(patch.PatchedCode)
	if !validationResult.Valid {
		return nil
	}
	patch.Confidence = point.Confidence
	patch.ConfidenceBreakdown = point.ConfidenceBreakdown
	patch.Artifact = buildArtifact(point, patch, validationResult)

	return patch
}

// buildSmartPatchedCode генерирует пропатченный код на основе SmartPatch стратегии
func (pg *PatchGenerator) buildSmartPatchedCode(point *PatchPoint, smartPatch *SmartPatch) string {
	header := point.MethodHeader
	if header == "" {
		access := "public"
		if !point.IsAppCode {
			access = "private"
		}
		header = fmt.Sprintf(".method %s %s%s",
			access, point.MethodName, pg.extractMethodDesc(point.MethodSignature))
	}

	// const_replace preserves the original method and edits only the matching
	// const-string instruction. Replacing the whole method with return-object
	// was invalid for void/primitive methods and destroyed surrounding control
	// flow even when the descriptor happened to be an object.
	if smartPatch.Strategy.Type == "const_replace" {
		return replaceSmartConstString(point.MethodBody, smartPatch.OriginalURL, smartPatch.Strategy.NewConst)
	}

	// Остальные стратегии → семантический, регистро-корректный возврат нужного типа
	// (см. patch_smali_builder.go: Boolean.TRUE/FALSE, пустые коллекции, боксинг и т.д.).
	var kind returnKind
	switch smartPatch.Strategy.Type {
	case "return_true":
		kind = kindTrue
	case "return_false":
		kind = kindFalse
	case "return_void":
		kind = kindVoid
	default:
		kind = patchKindFor(point.SuggestedPatch)
	}
	return buildStubMethodSmart(header, point.MethodSignature, point.ReturnType, kind)
}

func replaceSmartConstString(lines []string, original, replacement string) string {
	if len(lines) == 0 || original == "" {
		return ""
	}
	escaped := escapeSmaliString(replacement)
	out := append([]string(nil), lines...)
	replaced := 0
	for i, line := range out {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "const-string") || extractConstString(line) != original {
			continue
		}
		firstQuote := strings.Index(line, "\"")
		lastQuote := strings.LastIndex(line, "\"")
		if firstQuote < 0 || lastQuote <= firstQuote {
			continue
		}
		out[i] = line[:firstQuote+1] + escaped + line[lastQuote:]
		replaced++
	}
	if replaced == 0 {
		return ""
	}
	return strings.Join(out, "\n")
}

func escapeSmaliString(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"\n", "\\n",
		"\r", "\\r",
		"\t", "\\t",
	)
	return replacer.Replace(value)
}

// extractMethodDesc извлекает дескриптор метода из сигнатуры
func (pg *PatchGenerator) extractMethodDesc(signature string) string {
	idx := strings.Index(signature, "(")
	if idx < 0 {
		return "()V"
	}
	return signature[idx:]
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH GENERATE
// ═══════════════════════════════════════════════════════════════════════════════

// GenerateAll генерирует патчи для всех точек в prediction
func (pg *PatchGenerator) GenerateAll(prediction *PatchPrediction) map[string]*GeneratedPatch {
	patches := make(map[string]*GeneratedPatch)

	generateForList := func(points []PatchPoint) {
		for i := range points {
			point := &points[i]
			key := patchLookupKey(point.FilePath, point.MethodName, point.MethodSignature)
			patch := pg.Generate(point)
			if patch != nil {
				patches[key] = patch
			}
		}
	}

	generateForList(prediction.HighRisk)
	generateForList(prediction.MediumRisk)
	generateForList(prediction.LowRisk)

	return patches
}

// ═══════════════════════════════════════════════════════════════════════════════
// TERMINAL RENDER — вывод патча в терминал
// ═══════════════════════════════════════════════════════════════════════════════

// FormatForTerminal форматирует патч для вывода в терминал

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func isStaticMethod(header string) bool {
	return strings.Contains(strings.ToLower(header), " static ")
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	count := 1
	for _, c := range s {
		if c == '\n' {
			count++
		}
	}
	return count
}

// hasDualReturnShapes — два возврата доказывают два разных исхода только
// когда различаются их формы (опкод + операнд): два одинаковых `return v0`
// это один исход, а не dual-return. Критерий P2#8.
func hasDualReturnShapes(lines []string) bool {
	shapes := make(map[string]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "return") {
			continue
		}
		shapes[strings.Join(fields, " ")] = true
		if len(shapes) >= 2 {
			return true
		}
	}
	return false
}

func summarizeMethodBodyForStrategy(lines []string) (returnCount int, ifCount int, securityCalls []string, securityStrings []string, registerCount int, hasLocalsDirective bool) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Директивы регистров: первая встреченная задаёт бюджет (как в parseMethodBody).
		if strings.HasPrefix(trimmed, ".registers ") {
			if registerCount == 0 {
				registerCount = extractIntAfter(trimmed, ".registers ")
			}
			continue
		}
		if strings.HasPrefix(trimmed, ".locals ") {
			hasLocalsDirective = true
			if registerCount == 0 {
				registerCount = extractIntAfter(trimmed, ".locals ")
			}
			continue
		}

		if strings.HasPrefix(trimmed, "return") {
			returnCount++
		}
		if strings.HasPrefix(trimmed, "if-") {
			ifCount++
		}
		lower := strings.ToLower(trimmed)
		isSecurity := false
		for _, marker := range []string{"license", "premium", "billing", "integrity", "root", "emulator", "debug", "tamper", "signature", "xposed", "frida", "magisk", "hook"} {
			if strings.Contains(lower, marker) {
				isSecurity = true
				break
			}
		}
		if !isSecurity {
			continue
		}
		if strings.Contains(trimmed, "invoke-") {
			securityCalls = append(securityCalls, trimmed)
		}
		if strings.Contains(trimmed, "const-string") {
			securityStrings = append(securityStrings, trimmed)
		}
	}
	return returnCount, ifCount, securityCalls, securityStrings, registerCount, hasLocalsDirective
}
