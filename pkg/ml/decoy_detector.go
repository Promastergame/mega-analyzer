package ml

import (
	"strings"

	"mega-analyzer/pkg/ml/stringutils"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DECOY DETECTOR — Phase 4
//
// Negative-space analysis: что метод НЕ делает.
//
// Многие patch points выглядят подозрительно на pattern match (имя isLicensed,
// boolean return), но реально являются:
//   • уже патченными методами (всегда return true/false)
//   • opaque predicate'ами (ловушки от обфускатора — обе ветки идентичны)
//   • тривиальными getters/passthrough (не читают state)
//   • синтетическими bridges/accessor'ами (от компилятора)
//   • декорациями (read state, но result никем не используется)
//
// Эти методы попадают в HighRisk и забивают выдачу — реальные цели тонут.
// Phase 4 присваивает им штраф (DecoyConfidence × DecoyPenaltyFactor) в
// PatchValue, после чего они уезжают вниз приоритезации.
//
// Для каждого паттерна: чем выше Confidence, тем сильнее штраф.
// Финальный множитель к PatchValue: max(0.05, 1 - DecoyTotalPenalty).
// ═══════════════════════════════════════════════════════════════════════════════

// DecoyKind описывает тип "негативного сигнала" — что НЕ делает метод.
type DecoyKind string

const (
	DecoyAlwaysSameReturn   DecoyKind = "always_same_return"
	DecoyOpaquePredicate    DecoyKind = "opaque_predicate"
	DecoyTrivialPassthrough DecoyKind = "trivial_passthrough"
	DecoyBodyOnlyConst      DecoyKind = "body_only_const"
	DecoyLoggerOnly         DecoyKind = "logger_only"
	DecoyAccessor           DecoyKind = "accessor_synthetic"
	DecoyBridgeMethod       DecoyKind = "bridge_method"
	DecoyEmptyOrTinyBody    DecoyKind = "empty_or_tiny_body"
)

// DecoyMatch — найденный негативный сигнал.
type DecoyMatch struct {
	Kind        DecoyKind `json:"kind"`
	Confidence  float64   `json:"confidence"`  // 0..1
	Penalty     float64   `json:"penalty"`     // вклад в total decoy penalty
	Description string    `json:"description"` // человекочитаемое объяснение
}

// DecoyAnalysis — агрегат по методу. Если IsDecoy=true, метод понижается
// в приоритезации.
type DecoyAnalysis struct {
	IsDecoy         bool         `json:"is_decoy"`
	ConfidenceScore float64      `json:"confidence"`        // суммарная уверенность 0..1
	TotalPenalty    float64      `json:"total_penalty"`     // 0..1, применяется как (1 - p) к PatchValue
	Matches         []DecoyMatch `json:"matches,omitempty"` // конкретные find'ы
	PrimaryReason   string       `json:"primary_reason"`    // главная причина (для UI)
}

// Confidence implements DetectionResult interface.
func (d *DecoyAnalysis) Confidence() float64 {
	return d.ConfidenceScore
}

// Reason implements DetectionResult interface.
func (d *DecoyAnalysis) Reason() string {
	return d.PrimaryReason
}

// ShouldFilter implements DetectionResult interface.
func (d *DecoyAnalysis) ShouldFilter() bool {
	return d.IsDecoy
}

// DecoyPenaltyMultiplier возвращает множитель для PatchValue.
// Если decoy не найден — 1.0 (без изменений). Если найден — снижение пропорц.
// Минимум 0.05 — сохраняем минимальный сигнал даже для очевидных decoy'ев,
// чтобы они не исчезали полностью (полезно для аудита).
func (d *DecoyAnalysis) DecoyPenaltyMultiplier() float64 {
	if d == nil || !d.IsDecoy {
		return 1.0
	}
	mul := 1.0 - d.TotalPenalty
	if mul < 0.05 {
		mul = 0.05
	}
	return mul
}

// decoyConstantReturn reports a proven constant return: every return path
// yields the same literal, so no rewrite can change the method's value.
// Callers should clear the suggested patch but keep the finding for audit.
func decoyConstantReturn(d *DecoyAnalysis) bool {
	if d == nil || !d.IsDecoy { return false }
	for _, m := range d.Matches {
		if m.Kind == DecoyAlwaysSameReturn && m.Confidence >= 0.8 { return true }
	}
	return false
}

// AnalyzeDecoy запускает все детекторы decoy на методе.
// Возвращает nil если ничего не найдено — это значит метод "честный" (не decoy).
func AnalyzeDecoy(mi *MethodInfo) *DecoyAnalysis {
	if mi == nil {
		return nil
	}
	if isResourceValueMethod(mi) { return nil }
	if isEconomyTransactionMethod(mi) { return nil }

	// Security gates with real state/API reads are never decoys.
	if hasSecurityGateImmunity(mi) {
		return nil
	}

	matches := make([]DecoyMatch, 0, 8)

	// 0. Data class methods — equals, hashCode, toString — МАКСИМАЛЬНЫЙ ПРИОРИТЕТ
	// Эти методы НИКОГДА не являются security gates
	if m := detectDataClassMethod(mi); m != nil {
		matches = append(matches, *m)
		// Data class method — сразу early return с максимальным penalty
		return &DecoyAnalysis{
			IsDecoy:         true,
			ConfidenceScore: m.Confidence,
			TotalPenalty:    m.Penalty,
			Matches:         matches,
			PrimaryReason:   m.Description,
		}
	}

	// 0a. UI diff methods — areContentsTheSame, areItemsTheSame
	if m := detectContentTheSame(mi); m != nil {
		matches = append(matches, *m)
	}

	// 0b. Intrinsic getters — getIntrinsicWidth/Height
	if m := detectIntrinsicGetter(mi); m != nil {
		matches = append(matches, *m)
	}

	// 1. Empty / tiny body — самый дешёвый чек
	if m := detectEmptyOrTinyBody(mi); m != nil {
		matches = append(matches, *m)
	}

	// 2. Always same return: всегда `const X; return X` → уже патчено или decoy
	if m := detectAlwaysSameReturn(mi); m != nil {
		matches = append(matches, *m)
	}

	// 3. Body only const: тело = только const + return (нет invoke / iget / sget)
	if m := detectBodyOnlyConst(mi); m != nil {
		matches = append(matches, *m)
	}

	// 4. Trivial passthrough: param → return (нет проверок, нет logic)
	if m := detectTrivialPassthrough(mi); m != nil {
		matches = append(matches, *m)
	}

	// 5. Logger only: только Log.* / println / String.format calls
	if m := detectLoggerOnly(mi); m != nil {
		matches = append(matches, *m)
	}

	// 6. Accessor synthetic: access$xxx — компиляторный артефакт inner class
	if m := detectAccessor(mi); m != nil {
		matches = append(matches, *m)
	}

	// 7. Bridge method: synthetic для generics/inheritance
	if m := detectBridgeMethod(mi); m != nil {
		matches = append(matches, *m)
	}

	// 8. Opaque predicate: оба if-branch leads to same return (после flatten).
	// Реализуем упрощённый вариант: HasDualReturn=false + IfCheckCount>0 +
	// все returns одинаковые (проверка через RawBody).
	if m := detectOpaquePredicate(mi); m != nil {
		matches = append(matches, *m)
	}

	if len(matches) == 0 {
		return nil
	}

	// Агрегируем: total penalty = sum(match.Penalty), capped at 0.95
	var total float64
	var maxConf float64
	primary := matches[0].Description
	for _, m := range matches {
		total += m.Penalty
		if m.Confidence > maxConf {
			maxConf = m.Confidence
			primary = m.Description
		}
	}
	if total > 0.95 {
		total = 0.95
	}

	return &DecoyAnalysis{
		IsDecoy:         total >= 0.3, // threshold чтобы случайные мелкие сигналы не помечали как decoy
		ConfidenceScore: maxConf,
		TotalPenalty:    total,
		Matches:         matches,
		PrimaryReason:   primary,
	}
}

// ─── Detectors ────────────────────────────────────────────────────────────────

// detectEmptyOrTinyBody: < 3 значимых инструкций.
func detectEmptyOrTinyBody(mi *MethodInfo) *DecoyMatch {
	if mi.InstructionCount < 3 && !mi.IsAbstract {
		return &DecoyMatch{
			Kind:        DecoyEmptyOrTinyBody,
			Confidence:  0.95,
			Penalty:     0.6,
			Description: "method body too small for real check (< 3 instructions)",
		}
	}
	return nil
}

// detectAlwaysSameReturn: все return paths возвращают одну и ту же константу.
// Сигнал: уже патчено (return true для license bypass) или decoy.
func detectAlwaysSameReturn(mi *MethodInfo) *DecoyMatch {
	if mi.ReturnsVoid || mi.IsAbstract || mi.ReturnCount == 0 {
		return nil
	}

	// Соберём все return paths и предшествующие const'ы.
	// Простая эвристика: ищем pattern "const/4 vN, X" → "return vN".
	var returnVals []string
	var lastConst string
	for _, line := range mi.RawBody {
		t := strings.TrimSpace(strings.ToLower(line))
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ".") || strings.HasPrefix(t, ":") {
			continue
		}
		// Запоминаем последний const
		if strings.HasPrefix(t, "const/4") || strings.HasPrefix(t, "const/16") || strings.HasPrefix(t, "const ") || strings.HasPrefix(t, "const-string") {
			parts := strings.Split(t, ",")
			if len(parts) >= 2 {
				lastConst = strings.TrimSpace(parts[1])
			}
			continue
		}
		// На return проверяем, что предшествовало
		if strings.HasPrefix(t, "return") && !strings.Contains(t, "return-void") {
			if lastConst != "" {
				returnVals = append(returnVals, lastConst)
			} else {
				returnVals = append(returnVals, "?")
			}
			lastConst = ""
		}
	}

	if len(returnVals) == 0 {
		return nil
	}

	// Все return одинаковы и известны?
	first := returnVals[0]
	if first == "?" {
		return nil
	}
	for _, v := range returnVals {
		if v != first {
			return nil
		}
	}
	// Дополнительная защита: минимум 1 return + есть тело
	if mi.InstructionCount < 4 || mi.IfCheckCount > 0 {
		// Если есть if-проверки, то "одинаковый return" — это уже opaque predicate,
		// другой детектор справится. Здесь — только тривиальные единственные return.
		return nil
	}

	return &DecoyMatch{
		Kind:        DecoyAlwaysSameReturn,
		Confidence:  0.85,
		Penalty:     0.55,
		Description: "method always returns the same constant — likely already patched or decoy",
	}
}

// detectBodyOnlyConst: тело состоит только из const + return (нет invoke/iget/sget).
// Это значит метод не читает state — useless для проверки.
func detectBodyOnlyConst(mi *MethodInfo) *DecoyMatch {
	if mi.InstructionCount < 2 {
		return nil // empty-body детектор уже покрыл
	}

	hasInvoke := len(mi.Calls) > 0
	if hasInvoke {
		return nil
	}

	// Проверим: есть ли в RawBody iget/sget/aget? Если нет — нет state read.
	hasStateRead := false
	for _, line := range mi.RawBody {
		t := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(t, "iget") || strings.HasPrefix(t, "sget") || strings.HasPrefix(t, "aget") {
			hasStateRead = true
			break
		}
	}
	if hasStateRead {
		return nil
	}

	// Метод не читает state и не вызывает invoke. Если return существует, это decoy.
	if mi.ReturnCount > 0 {
		return &DecoyMatch{
			Kind:        DecoyBodyOnlyConst,
			Confidence:  0.8,
			Penalty:     0.5,
			Description: "method body only contains const+return (no state read, no invoke) — decoy",
		}
	}
	return nil
}

// detectTrivialPassthrough: param → return без логики.
// Сигнатура: один параметр, тело: move-result-from-param + return.
func detectTrivialPassthrough(mi *MethodInfo) *DecoyMatch {
	if mi.InstructionCount > 4 {
		return nil
	}
	if mi.IfCheckCount > 0 || len(mi.Calls) > 0 {
		return nil // есть логика
	}

	// Простая эвристика: ищем "return p0/p1/v0" без предшествующего const
	for _, line := range mi.RawBody {
		t := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(t, "return p") || strings.HasPrefix(t, "return-object p") {
			return &DecoyMatch{
				Kind:        DecoyTrivialPassthrough,
				Confidence:  0.7,
				Penalty:     0.4,
				Description: "trivial param passthrough (return param without logic) — getter, not check",
			}
		}
	}
	return nil
}

// detectLoggerOnly: метод только логирует (Log.* / println).
// Признак: все calls — logger calls; нет if-, нет state read.
func detectLoggerOnly(mi *MethodInfo) *DecoyMatch {
	if len(mi.Calls) == 0 {
		return nil
	}
	if mi.IfCheckCount > 0 {
		return nil // есть проверки → не logger
	}

	loggerCount := 0
	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		if strings.Contains(full, "android/util/log") ||
			strings.Contains(full, "java/io/printstream;->print") ||
			strings.Contains(full, "system;->out") ||
			strings.Contains(full, "java/lang/system;->out") ||
			strings.Contains(full, "java/lang/string;->format") {
			loggerCount++
		}
	}

	// Все calls — logger?
	if loggerCount > 0 && loggerCount == len(mi.Calls) {
		return &DecoyMatch{
			Kind:        DecoyLoggerOnly,
			Confidence:  0.75,
			Penalty:     0.45,
			Description: "method only contains logger calls — no real check logic",
		}
	}
	return nil
}

// detectAccessor: synthetic accessor (access$xxx, имя-числа после $).
// Это compiler-generated wrapper для inner class private access.
func detectAccessor(mi *MethodInfo) *DecoyMatch {
	if mi.IsAccessor {
		return &DecoyMatch{
			Kind:        DecoyAccessor,
			Confidence:  0.9,
			Penalty:     0.5,
			Description: "synthetic accessor (access$NNN) — compiler-generated wrapper",
		}
	}
	// Доп. проверка по pattern если флаг не установлен:
	if strings.Contains(strings.ToLower(mi.Name), "access$") {
		return &DecoyMatch{
			Kind:        DecoyAccessor,
			Confidence:  0.85,
			Penalty:     0.45,
			Description: "name suggests accessor pattern (access$)",
		}
	}
	return nil
}

// detectBridgeMethod: synthetic bridge для generics / interface inheritance.
// Признак: IsSynthetic + крайне короткое тело + invoke-virtual + return.
func detectBridgeMethod(mi *MethodInfo) *DecoyMatch {
	if !mi.IsSynthetic {
		return nil
	}
	if mi.InstructionCount > 6 || mi.IfCheckCount > 0 {
		return nil
	}
	// Bridge typically has: check-cast → invoke-virtual → return
	hasInvokeVirtual := false
	hasCheckCast := false
	for _, line := range mi.RawBody {
		t := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(t, "invoke-virtual") {
			hasInvokeVirtual = true
		}
		if strings.HasPrefix(t, "check-cast") {
			hasCheckCast = true
		}
	}
	if hasInvokeVirtual && hasCheckCast {
		return &DecoyMatch{
			Kind:        DecoyBridgeMethod,
			Confidence:  0.85,
			Penalty:     0.45,
			Description: "synthetic bridge method (cast + delegate) — compiler-generated",
		}
	}
	return nil
}

// detectDataClassMethod: equals, hashCode, toString, compareTo — точно не gates.
// Эти методы сравнивают объекты, а не проверяют лицензию.
func detectDataClassMethod(mi *MethodInfo) *DecoyMatch {
	nameLower := strings.ToLower(mi.Name)

	for _, dataMethod := range DataClassMethodNames {
		if nameLower == dataMethod {
			return &DecoyMatch{
				Kind:        DecoyAlwaysSameReturn,
				Confidence:  0.95,
				Penalty:     0.95, // Почти полный штраф
				Description: dataMethod + "() — data class method, NOT security gate",
			}
		}
	}

	// Геттеры: getXxx() где Xxx — PropertyName
	if strings.HasPrefix(nameLower, "get") && len(mi.Name) > 3 {
		nextChar := mi.Name[3]
		if nextChar >= 'A' && nextChar <= 'Z' {
			// Проверяем что это не "getLicense" или "getPremiumStatus"
			if !stringutils.ContainsAny(nameLower, SecurityNameKeywords) {
				return &DecoyMatch{
					Kind:        DecoyAccessor,
					Confidence:  0.80,
					Penalty:     0.75,
					Description: "getter method (getXxx) — property accessor, NOT security gate",
				}
			}
		}
	}

	// Boolean геттеры: isXxx() где Xxx — состояние
	if strings.HasPrefix(nameLower, "is") && len(mi.Name) > 2 {
		nextChar := mi.Name[2]
		if nextChar >= 'A' && nextChar <= 'Z' {
			// isEnabled, isValid — геттеры
			// isLicensed, isPremium — это может быть gate
			if stringutils.ContainsAny(nameLower, NonSecurityGetterPatterns) {
				return &DecoyMatch{
					Kind:        DecoyAccessor,
					Confidence:  0.75,
					Penalty:     0.70,
					Description: "boolean getter (is" + mi.Name[2:] + ") — state accessor, NOT security gate",
				}
			}
		}
	}

	return nil
}

// detectContentTheSame: areContentsTheSame — RecyclerView/DiffUtil метод
// Это НЕ security gate, это UI optimization
func detectContentTheSame(mi *MethodInfo) *DecoyMatch {
	nameLower := strings.ToLower(mi.Name)

	if stringutils.ContainsAny(nameLower, UIDiffPatterns) {
		return &DecoyMatch{
			Kind:        DecoyTrivialPassthrough,
			Confidence:  0.80,
			Penalty:     0.75,
			Description: "UI diff/payload method — RecyclerView optimization, NOT security gate",
		}
	}

	return nil
}

// detectIntrinsicGetter: getIntrinsicWidth/Height — Android Drawable методы
func detectIntrinsicGetter(mi *MethodInfo) *DecoyMatch {
	nameLower := strings.ToLower(mi.Name)

	if stringutils.ContainsAny(nameLower, IntrinsicPatterns) {
		return &DecoyMatch{
			Kind:        DecoyAccessor,
			Confidence:  0.85,
			Penalty:     0.80,
			Description: "intrinsic getter (Drawable method) — UI property, NOT security gate",
		}
	}

	return nil
}

// detectOpaquePredicate (упрощённая версия): IfCheckCount > 0, но HasDualReturn=false
// (все returns одинаковы) и нет state read через iget/sget.
// Это значит if-проверка не влияет на return — opaque predicate.
func detectOpaquePredicate(mi *MethodInfo) *DecoyMatch {
	if mi.IfCheckCount == 0 || mi.HasDualReturn {
		return nil
	}
	if mi.ReturnCount < 2 {
		return nil // только 1 return — нечего сравнивать
	}

	// Считаем уникальные const-перед-return значения.
	// Если все одинаковые — opaque predicate.
	var returnVals []string
	var lastConst string
	for _, line := range mi.RawBody {
		t := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(t, "const/4") || strings.HasPrefix(t, "const/16") || strings.HasPrefix(t, "const ") {
			parts := strings.Split(t, ",")
			if len(parts) >= 2 {
				lastConst = strings.TrimSpace(parts[1])
			}
			continue
		}
		if strings.HasPrefix(t, "return") && !strings.Contains(t, "return-void") {
			if lastConst != "" {
				returnVals = append(returnVals, lastConst)
			}
			lastConst = ""
		}
	}

	if len(returnVals) < 2 {
		return nil
	}
	first := returnVals[0]
	for _, v := range returnVals {
		if v != first {
			return nil // разные returns — реальная логика
		}
	}

	return &DecoyMatch{
		Kind:        DecoyOpaquePredicate,
		Confidence:  0.7,
		Penalty:     0.4,
		Description: "if-check exists but all returns are identical — opaque predicate (obfuscator trap)",
	}
}

// hasSecurityGateImmunity returns true when the method shows real security gate behavior
// (state reads, billing/integrity APIs) and must not be down-ranked as a decoy.
func hasSecurityGateImmunity(mi *MethodInfo) bool {
	pathLower := strings.ToLower(mi.FilePath + " " + mi.ClassName)
	for _, hint := range SecurityClassHints {
		if strings.Contains(pathLower, hint) {
			return true
		}
	}

	hits := 0
	for _, sig := range SecurityInvokes {
		if rawBodyContainsFold(mi.RawBody, sig) {
			hits++
			if hits >= 2 {
				return true
			}
		}
	}
	return false
}
