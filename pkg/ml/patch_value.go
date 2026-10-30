package ml

import (
	"fmt"
	"math"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH VALUE — Phase 3
//
// Главная метрика для реверсера: «что патчить ПЕРВЫМ».
//
// Раньше patch points сортировались только по RiskScore — но «уязвимый» не
// равно «легко патчится». PatchValue умножает RiskScore на CrackingImpact
// (что именно ломается одним патчем) и делит на BypassCost (сколько мест
// надо править), DetectionRisk (anti-tamper рядом), BreakageRisk (поломка
// приложения).
//
//   PatchValue = (RiskScore × CrackingImpact) / (BypassCost × DetectionRisk × BreakageRisk)
//
// На выходе:
//   PatchValue ≈ 8-10  → 🥇 топ-цель (HARD GATE, single patch, low risk)
//   PatchValue ≈ 4-7   → 🥈 нормальная цель
//   PatchValue ≈ 1-3   → 🥉 спорно (decoy / native / chain)
//   PatchValue < 1     → не патчить (anti-tamper или dead code)
// ═══════════════════════════════════════════════════════════════════════════════

// PatchValueBreakdown — сегментированный расчёт для UI / audit.
type PatchValueBreakdown struct {
	Value float64 `json:"value"`

	// Числитель
	RiskScoreInput float64 `json:"risk_score"`
	CrackingImpact float64 `json:"cracking_impact"`
	ImpactReason   string  `json:"impact_reason"`

	// Знаменатель
	BypassCost      float64 `json:"bypass_cost"`
	BypassReason    string  `json:"bypass_reason"`
	DetectionRisk   float64 `json:"detection_risk"`
	DetectionReason string  `json:"detection_reason"`
	BreakageRisk    float64 `json:"breakage_risk"`
	BreakageReason  string  `json:"breakage_reason"`

	// Penalty flags
	DecoyPenalty bool `json:"decoy_penalty,omitempty"`
}

// ComputePatchValue считает PatchValue для уже сформированной PatchPoint.
// Полагается на Phase 1+2 поля: RiskScore, Structural, DFG, Method.Calls.
func ComputePatchValue(p *PatchPoint, mi *MethodInfo) *PatchValueBreakdown {
	if p == nil {
		return nil
	}
	b := &PatchValueBreakdown{
		RiskScoreInput: p.RiskScore,
	}

	// CrackingImpact и BypassCost — взаимосвязаны через Structural.
	b.CrackingImpact, b.ImpactReason, b.BypassCost, b.BypassReason = computeImpactAndCost(p, mi)

	// DetectionRisk — anti-tamper proximity.
	b.DetectionRisk, b.DetectionReason = computeDetectionRisk(mi)

	// BreakageRisk — структурная совместимость патча.
	b.BreakageRisk, b.BreakageReason = computeBreakageRisk(p, mi)

	// Финальная формула. Знаменатель не должен делиться на 0.
	denom := b.BypassCost * b.DetectionRisk * b.BreakageRisk
	if denom <= 0 {
		denom = 1.0
	}
	b.Value = (b.RiskScoreInput * b.CrackingImpact) / denom

	if p.CrackPointConfirmed {
		b.CrackingImpact = math.Min(1.0, b.CrackingImpact+0.25)
		b.Value *= 1.35
		b.ImpactReason += " + CFG crack-point confirmed"
	}

	// Нормализация в разумный диапазон. RiskScore до 100, CrackingImpact до 1,
	// нормальный знаменатель ~1, поэтому сырое значение ≈ 0..100. Делим на 10
	// чтобы получить понятную шкалу 0..10.
	b.Value /= 10.0

	return b
}

// computeImpactAndCost определяет class патча: HARD GATE / AND-funnel entry /
// AND-funnel inner / decoy / regular.
func computeImpactAndCost(p *PatchPoint, _ *MethodInfo) (
	impact float64, impactReason string,
	cost float64, costReason string,
) {
	// Базовые значения — нейтральный случай.
	impact = 0.5
	impactReason = "regular check (no path-sensitive amplifier)"
	cost = 1.0
	costReason = "single method patch"

	if p.Structural == nil {
		return
	}
	s := p.Structural

	// HARD GATE: guard постдоминирует exit → один патч ломает 100% поведения метода.
	if s.HardGateCount > 0 {
		impact = 1.0
		impactReason = fmt.Sprintf("HARD GATE — %d guard(s) post-dominate exit", s.HardGateCount)
		cost = 1.0
		costReason = "single patch (hard gate flip)"
		return
	}

	// AND-funnel: цепочка проверок. Одного патча entry достаточно.
	if s.HasAndFunnel && s.GuardCount >= 2 {
		impact = 1.0
		impactReason = fmt.Sprintf("AND-funnel entry — %d guards in chain", s.GuardCount)
		// BypassCost: сделать единичным если можем патчить funnel-entry; иначе
		// нужно N патчей. Здесь упрощённая эвристика: считаем что patch-стратегия
		// PatchBypassFunnel (когда появится в Phase 5) даёт cost=1, иначе N.
		cost = 1.0
		costReason = "single entry-of-funnel patch breaks chain"
		return
	}

	// Inner check внутри AND-funnel — если у нас несколько guards, но funnel
	// не AND, или мы ОДИН из N — нужно патчить N.
	if s.FunnelCount > 0 && s.GuardCount >= 2 && !s.HasAndFunnel {
		impact = 1.0 / float64(s.GuardCount)
		impactReason = fmt.Sprintf("OR-funnel — 1/%d of failure paths", s.GuardCount)
		cost = float64(s.GuardCount)
		costReason = fmt.Sprintf("OR-funnel: %d separate patches needed", s.GuardCount)
		return
	}

	// Soft gate: есть guards, но не hard.
	if s.GuardCount > 0 {
		impact = 0.7
		impactReason = fmt.Sprintf("SOFT GATE — %d guard(s), no post-domination", s.GuardCount)
		cost = 1.0
		costReason = "single guard flip"
		return
	}

	// Decoy: ни guards, ни funnels — но мы здесь только если RiskScore высокий
	// (иначе patch point не попал бы в High/Medium). Это значит pattern match
	// сильный, но structural — слабый. Пометим как decoy-suspect.
	impact = 0.3
	impactReason = "no path-sensitive structure (possible decoy or already-broken check)"
	cost = 1.0
	costReason = "single method patch"
	return
}

// computeDetectionRisk оценивает, насколько метод может «заметить» патч.
// Чем больше anti-tamper API в окрестности — тем выше risk.
func computeDetectionRisk(mi *MethodInfo) (risk float64, reason string) {
	risk = 1.0
	reason = "no anti-tamper signals"

	if mi == nil {
		return
	}

	// Сканируем calls на anti-tamper индикаторы.
	// Имена нормализуем через ToLower; реальные класспaths могут быть с
	// разделителями `/`, поэтому matcher'ы используют широкие подстроки
	// (например `play/core/integrity`, `integritymanager`).
	hasSafetyNet := false
	hasPlayIntegrity := false
	hasSignatureCheck := false
	hasNativeBridge := false

	for _, c := range mi.Calls {
		full := strings.ToLower(c.FullCall)
		// PlayIntegrity API (com.google.android.play.core.integrity)
		if strings.Contains(full, "playintegrity") ||
			strings.Contains(full, "play_integrity") ||
			strings.Contains(full, "play/core/integrity") ||
			strings.Contains(full, "integritymanager") ||
			strings.Contains(full, "integrityservice") {
			hasPlayIntegrity = true
		}
		// SafetyNet API (com.google.android.gms.safetynet)
		if strings.Contains(full, "safetynet") ||
			strings.Contains(full, "gms/safety") {
			hasSafetyNet = true
		}
		// Signature check via PackageManager
		if (strings.Contains(full, "getpackageinfo") && strings.Contains(full, "signatur")) ||
			strings.Contains(full, "packagemanager;->getpackageinfo") {
			hasSignatureCheck = true
		}
		// Native bridge
		if strings.Contains(full, "loadlibrary") || strings.Contains(full, "system/load") {
			hasNativeBridge = true
		}
	}

	signals := []string{}
	switch {
	case hasPlayIntegrity:
		risk = 2.5
		signals = append(signals, "PlayIntegrity")
	case hasSafetyNet:
		risk = 2.0
		signals = append(signals, "SafetyNet")
	case hasSignatureCheck:
		risk = 1.7
		signals = append(signals, "Signature check")
	}

	if hasNativeBridge {
		risk += 0.5
		signals = append(signals, "native bridge")
	}

	if len(signals) > 0 {
		reason = "anti-tamper proximity: " + strings.Join(signals, ", ")
	}

	return
}

// computeBreakageRisk оценивает, насколько патч может сломать приложение.
// Учитывает: тип возврата vs strategy, сколько callers потребляют результат.
func computeBreakageRisk(p *PatchPoint, mi *MethodInfo) (risk float64, reason string) {
	risk = 1.0
	reason = "structural compatibility OK"

	if p == nil || mi == nil {
		return
	}

	// Несовместимость return-type ↔ patch strategy.
	switch p.SuggestedPatch {
	case PatchReturnTrue, PatchReturnFalse:
		// Boolean-стратегия требует Z.
		if mi.ReturnType != "Z" {
			risk = 2.0
			reason = fmt.Sprintf("strategy %s needs boolean return, method returns %s",
				p.SuggestedPatch, mi.ReturnType)
			return
		}
	case PatchReturnVoid:
		// Void-стратегия только на V.
		if mi.ReturnType != "V" {
			risk = 2.0
			reason = fmt.Sprintf("strategy return_void needs V, method returns %s", mi.ReturnType)
			return
		}
	case PatchReturnMaxInt:
		// Int-стратегия: I, J, или ничего проверим.
		if mi.ReturnType != "I" && mi.ReturnType != "J" {
			risk = 1.8
			reason = fmt.Sprintf("strategy return_zero typically for I/J, method returns %s", mi.ReturnType)
			return
		}
	}

	// Если у метода много invokes но мало returns — патчить ризк выше
	// (метод делает работу, не только проверку).
	if mi.InstructionCount > 30 && len(mi.Calls) > 5 {
		risk = 1.3
		reason = fmt.Sprintf("complex method (%d instr, %d calls) — patch may skip side-effects",
			mi.InstructionCount, len(mi.Calls))
		return
	}

	return
}

// Tier классифицирует PatchValue в текстовый тир для UI.
func (b *PatchValueBreakdown) Tier() string {
	if b == nil {
		return "?"
	}
	switch {
	case b.Value >= 7.0:
		return "🥇 TOP"
	case b.Value >= 4.0:
		return "🥈 GOOD"
	case b.Value >= 2.0:
		return "🥉 OK"
	default:
		return "⚠ LOW"
	}
}

// Explain возвращает однострочное объяснение PatchValue для UI.
func (b *PatchValueBreakdown) Explain() string {
	if b == nil {
		return ""
	}
	return fmt.Sprintf(
		"PatchValue=%.1f [%s] = (Risk %.1f × Impact %.2f) / (Cost %.1f × Detect %.1f × Break %.1f)",
		b.Value, b.Tier(),
		b.RiskScoreInput, b.CrackingImpact,
		b.BypassCost, b.DetectionRisk, b.BreakageRisk,
	)
}
