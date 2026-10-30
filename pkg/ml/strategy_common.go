package ml

import (
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY COMMON — общие таблицы и хелперы для всех стратегий
//
// Убирает дубли conditionalInversions, чинит полярность NOP и дает селектору
// понимание "гибких" стратегий (constant injection умеет и true и false).
// ═══════════════════════════════════════════════════════════════════════════════

// SharedConditionalInversions — каноническая таблица инверсий.
// Единственный источник правды для ConditionInversion + PartialBypass.
var SharedConditionalInversions = map[string]string{
	"if-eqz": "if-nez",
	"if-nez": "if-eqz",
	"If-eq":  "if-ne", // placeholder, replaced below (case-sensitive fix)
}

// sharedInversionsInit патчит опечатку выше при init (чтобы diff был наглядным).
func init() {
	delete(SharedConditionalInversions, "If-eq")
	for k, v := range map[string]string{
		"if-eq":  "if-ne",
		"if-ne":  "if-eq",
		"if-lt":  "if-ge",
		"if-ge":  "if-lt",
		"if-gt":  "if-le",
		"if-le":  "if-gt",
		"if-ltz": "if-gez",
		"if-gez": "if-ltz",
		"if-gtz": "if-lez",
		"if-lez": "if-gtz",
	} {
		SharedConditionalInversions[k] = v
	}
}

// InvertConditionalOpcode возвращает инверсию опкода и true если он условный.
func InvertConditionalOpcode(opcode string) (string, bool) {
	inv, ok := SharedConditionalInversions[opcode]
	return inv, ok
}

// IsConditionalOpcode сообщает, является ли мнемоника условным переходом.
func IsConditionalOpcode(opcode string) bool {
	_, ok := SharedConditionalInversions[opcode]
	return ok
}

// InvertConditionalLine инвертирует условную инструкцию с сохранением отступа.
// Возвращает новую строку и true если инверсия применена.
func InvertConditionalLine(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	for original, inverted := range SharedConditionalInversions {
		if strings.HasPrefix(trimmed, original+" ") || trimmed == original {
			indent := line[:len(line)-len(trimmed)]
			rest := strings.TrimPrefix(trimmed[len(original):], " ")
			if rest == "" {
				return indent + inverted, true
			}
			// сохраняем оригинальный разделитель (обычно один пробел)
			sep := trimmed[len(original) : len(trimmed)-len(rest)]
			return indent + inverted + sep + rest, true
		}
	}
	return line, false
}

// ═══════════════════════════════════════════════════════════════════════════════
// FLEXIBLE PATCH TYPES — стратегии, умеющие несколько исходов
// ═══════════════════════════════════════════════════════════════════════════════

// FlexiblePatchTypes реализуется стратегиями, которые умеют производить
// несколько PatchType (например ConstantInjection: true И false).
// Селектор использует это для signal-буста вместо PatchType().
type FlexiblePatchTypes interface {
	SupportedPatchTypes() []PatchType
}

// strategySupportsDesired сообщает, матчится ли стратегия на desired-сигнал.
// Понимает как PatchType(), так и FlexiblePatchTypes.
func strategySupportsDesired(strategy PatchStrategy, desired string) bool {
	if desired == "" || strategy == nil {
		return false
	}
	if fp, ok := strategy.(FlexiblePatchTypes); ok {
		for _, pt := range fp.SupportedPatchTypes() {
			if string(pt) == desired {
				return true
			}
		}
	}
	return string(strategy.PatchType()) == desired
}

// ═══════════════════════════════════════════════════════════════════════════════
// NOP POLARITY — какое значение заливать в orphaned move-result
// ═══════════════════════════════════════════════════════════════════════════════

// nopFillValue решает, что писать в move-result после выпиленного invoke:
//   - detection-пробы (isRooted/isDebugger/isTampered) → 0 ("угрозы нет")
//   - positive-gates (isLicensed/hasPremium) → 1 ("доступ есть")
//
// Эвристика: сначала ContextAnalyzer (класс/пакет/имя), НО только если он
// уверенно классифицировал (не Unknown): обфусцированные имена вроде zzcheck
// иначе дают Unknown → дефолтный True → неверная 1. Для Unknown смотрим
// SecurityCalls/SecurityStrings/тело по полярным словам, потом fallback 0
// (безопаснее для детектов — их большинство).
func nopFillValue(mi *shared.MethodInfo, mode PatchMode) int {
	if mi == nil {
		return 0
	}
	ca := NewContextAnalyzer()
	checkType := ca.DetermineCheckType(mi)
	if checkType != shared.CheckTypeUnknown {
		desired := ca.GetDesiredReturn(checkType, mode)
		// GetDesiredReturn уже учитывает mode: defensive усиливает детект,
		// research открывает доступ. NOP-заливка должна совпадать с desired.
		switch desired {
		case shared.PatchReturnTrue:
			return 1
		case shared.PatchReturnFalse:
			return 0
		}
	}
	// Unknown-контекст: классифицируем по вызовам/строкам/телу.
	// SecurityCalls вида Lsec;->isRooted()Z — сильнейший сигнал детекта.
	callBlob := strings.ToLower(strings.Join(mi.SecurityCalls, "\n"))
	strBlob := strings.ToLower(strings.Join(mi.SecurityStrings, "\n"))
	name := strings.ToLower(mi.Name)
	body := ""
	if len(mi.RawBody) > 0 {
		body = strings.ToLower(strings.Join(mi.RawBody, "\n"))
	}
	neg, pos := 0, 0
	blobs := []struct {
		text   string
		weight int
	}{
		{name, 3}, {callBlob, 3}, {strBlob, 2}, {body, 1},
		{strings.ToLower(mi.ClassName), 2},
	}
	for _, b := range blobs {
		if b.text == "" {
			continue
		}
		for _, w := range negativePolarityWords {
			if strings.Contains(b.text, w) {
				neg += b.weight
			}
		}
		for _, w := range positivePolarityWords {
			if strings.Contains(b.text, w) {
				pos += b.weight
			}
		}
	}
	if pos > neg {
		return 1
	}
	return 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// FUNNEL CLASSIFIER — OR-gated vs AND-gated методы (легкий CFG)
// ═══════════════════════════════════════════════════════════════════════════════

// FunnelKind описывает, как ветки ведут к возвратам.
type FunnelKind string

const (
	FunnelUnknown FunnelKind = "unknown"
	FunnelOR      FunnelKind = "or_gated"  // любой чек → detected (инвертируй все)
	FunnelAND     FunnelKind = "and_gated" // все чеки → success (трогай entry-gate)
	FunnelSingle  FunnelKind = "single"    // одна ветка / линейный метод
)

// ClassifyFunnel эвристически классифицирует метод по числу if и возвратов.
// Полноценный CFG строится из smaliUnits+branchRange в smali_cfg.go;
// здесь — быстрый текстовый скоринг, достаточный для выбора
// "инвертировать все" vs "только entry-gate".
func ClassifyFunnel(ifCount int, hasDualReturn bool, rawBody []string) FunnelKind {
	if ifCount == 0 || len(rawBody) == 0 {
		return FunnelSingle
	}
	if !hasDualReturn {
		return FunnelSingle
	}
	// Подсчет const-значений, кормящих return: классический dual-return
	// boolean-идиом (const 0 / const 1 перед return) — признак OR-gated детекта.
	zeroReturns, oneReturns := 0, 0
	for i, line := range rawBody {
		trimmed := strings.TrimSpace(line)
		reg, ok := plainReturnRegister(trimmed)
		if !ok {
			continue
		}
		// ищем ближайший const на тот же регистр выше
		for j := i - 1; j >= 0 && j >= i-4; j-- {
			pt := strings.TrimSpace(rawBody[j])
			if dreg, ok := constDestRegister(pt); ok && dreg == reg {
				if cur, lok := constLiteralValue(pt); lok {
					if cur == 0 {
						zeroReturns++
					} else if cur == 1 {
						oneReturns++
					}
				}
				break
			}
		}
	}
	if ifCount >= 3 {
		return FunnelAND // длинная цепочка — безопаснее entry-gate
	}
	if zeroReturns > 0 && oneReturns > 0 {
		return FunnelOR
	}
	return FunnelUnknown
}
