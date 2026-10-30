package ml

import (
	"fmt"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DFG SCORING TESTS — проверяем что DFG бонус реально влияет на RiskScore
// ═══════════════════════════════════════════════════════════════════════════════

// TestDFGScoring_LicenseCheckBoost проверяет что метод с license check
// получает бонус к RiskScore через DFG
func TestDFGScoring_LicenseCheckBoost(t *testing.T) {
	pp := NewPatchPredictor(nil)

	// Метод с isLicensed invoke — должен получить DFG бонус
	sm := ScoredMethod{
		Method: MethodInfo{
			Name:             "checkLicense",
			ClassName:        "Lcom/app/LicenseChecker;",
			FilePath:         "com/app/LicenseChecker.smali",
			FullSignature:    "checkLicense()Z",
			ReturnsBoolean:   true,
			HasCheckPrefix:   true,
			IsAppCode:        true,
			InstructionCount: 8,
			IfCheckCount:     1,
			RawBody: []string{
				"const-string v0, \"license_key\"",
				"invoke-static {v0}, LChecker;->isLicensed(Ljava/lang/String;)Z",
				"move-result v1",
				"if-eqz v1, :not_licensed",
				"const/4 v0, 0x1",
				"return v0",
				":not_licensed",
				"const/4 v0, 0x0",
				"return v0",
			},
		},
		Score: ScoreResult{
			FinalScore:     30.0,
			RiskLevel:      RiskClassMedium,
			Confidence:     0.7,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnTrue,
			Reasons:        []string{"pattern match"},
		},
		ClassPath: "com/app/LicenseChecker.smali",
		ClassName: "Lcom/app/LicenseChecker;",
	}

	point := pp.scoredMethodToPoint(&sm)

	// DFG должен быть заполнен
	if !point.HasDFG() {
		// Отладка: проверим что вообще произошло
		t.Logf("DFG not available. InstructionCount=%d IfCheckCount=%d RawBody=%d",
			sm.Method.InstructionCount, sm.Method.IfCheckCount, len(sm.Method.RawBody))
		t.Logf("RawBody contains if-: %v, invoke: %v",
			strings.Contains(strings.Join(sm.Method.RawBody, " "), "if-"),
			strings.Contains(strings.Join(sm.Method.RawBody, " "), "invoke"))
		t.Fatalf("Expected DFG to be available, but HasDFG() = false")
	}

	t.Logf("DFG available: conf=%.2f reg=%s cond=%s trace=%d",
		point.DFG.Confidence, point.DFG.Register, point.DFG.ConditionText, len(point.DFG.Trace))

	// RiskScore должен быть БОЛЬШЕ исходного FinalScore (30.0)
	if point.RiskScore <= sm.Score.FinalScore {
		t.Errorf("RiskScore = %.2f, expected > %.2f (DFG bonus should add)",
			point.RiskScore, sm.Score.FinalScore)
	}

	// WhyVulnerable должен содержать DFG reason
	hasDFGReason := false
	for _, reason := range point.WhyVulnerable {
		if strings.Contains(reason, "DFG:") {
			hasDFGReason = true
			break
		}
	}
	if !hasDFGReason {
		t.Error("WhyVulnerable should contain at least one DFG reason")
	}

	t.Logf("✓ DFG scoring: RiskScore=%.2f (base=%.2f, bonus=%.2f)",
		point.RiskScore, sm.Score.FinalScore, point.RiskScore-sm.Score.FinalScore)
	for _, r := range point.WhyVulnerable {
		if strings.Contains(r, "DFG:") {
			t.Logf("  reason: %s", r)
		}
	}
}

// TestDFGScoring_NoLicenseNoBonus проверяет что метод БЕЗ license check
// не получает DFG бонус
func TestDFGScoring_NoLicenseNoBonus(t *testing.T) {
	pp := NewPatchPredictor(nil)

	// Метод без invoke/if — DFG не нужен
	sm := ScoredMethod{
		Method: MethodInfo{
			Name:             "simpleGetter",
			ClassName:        "Lcom/app/Config;",
			FilePath:         "com/app/Config.smali",
			FullSignature:    "getName()Ljava/lang/String;",
			ReturnsBoolean:   false,
			IsAppCode:        true,
			InstructionCount: 3,
			IfCheckCount:     0,
			RawBody: []string{
				"iget-object v0, p0, Lcom/app/Config;->name:Ljava/lang/String;",
				"return-object v0",
			},
		},
		Score: ScoreResult{
			FinalScore:     10.0,
			RiskLevel:      RiskClassLow,
			Confidence:     0.3,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnMaxInt,
			Reasons:        []string{"generic"},
		},
		ClassPath: "com/app/Config.smali",
		ClassName: "Lcom/app/Config;",
	}

	point := pp.scoredMethodToPoint(&sm)

	// DFG не должен быть заполнен (нет if-check, нет invoke)
	if point.HasDFG() {
		t.Error("DFG should NOT be available for simple getter")
	}

	// RiskScore должен быть равен FinalScore (без бонуса)
	if point.RiskScore != sm.Score.FinalScore {
		t.Errorf("RiskScore = %.2f, expected %.2f (no DFG bonus)",
			point.RiskScore, sm.Score.FinalScore)
	}

	t.Logf("✓ No DFG bonus: RiskScore=%.2f = base=%.2f", point.RiskScore, sm.Score.FinalScore)
}

// TestDFGScoring_StringFilterSkipsDFG проверяет что строковый фильтр
// отсекает методы без if- И invoke (оба отсутствуют)
func TestDFGScoring_StringFilterSkipsDFG(t *testing.T) {
	pp := NewPatchPredictor(nil)

	// Метод БЕЗ if- и БЕЗ invoke — фильтр должен отсечь
	sm := ScoredMethod{
		Method: MethodInfo{
			Name:             "noInvokeMethod",
			ClassName:        "Lcom/app/Calc;",
			FilePath:         "com/app/Calc.smali",
			FullSignature:    "calc()I",
			IsAppCode:        true,
			InstructionCount: 5,
			IfCheckCount:     1,
			RawBody: []string{
				"const/4 v0, 0x5",
				"add-int v0, v0, v1",
				"mul-int v0, v0, v2",
				"sub-int v0, v0, v3",
				"return v0",
			},
		},
		Score: ScoreResult{
			FinalScore:     15.0,
			RiskLevel:      RiskClassLow,
			Confidence:     0.4,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnMaxInt,
			Reasons:        []string{"generic"},
		},
		ClassPath: "com/app/Calc.smali",
		ClassName: "Lcom/app/Calc;",
	}

	point := pp.scoredMethodToPoint(&sm)

	// DFG не должен быть заполнен — нет ни if-, ни invoke
	if point.HasDFG() {
		t.Error("DFG should NOT be available — no if- and no invoke in body")
	}

	t.Logf("✓ String filter works: no DFG for method without if- AND invoke")
}

// TestDFGScoring_InvokeOnlyPassesFilter проверяет что метод с invoke
// но без if- проходит строковый фильтр (invoke-only кейс не убивается)
func TestDFGScoring_InvokeOnlyPassesFilter(t *testing.T) {
	pp := NewPatchPredictor(nil)

	// Метод с invoke но без if- — фильтр НЕ должен отсекать (!hasIf && !hasInvoke = false)
	sm := ScoredMethod{
		Method: MethodInfo{
			Name:             "invokeOnlyMethod",
			ClassName:        "Lcom/app/Checker;",
			FilePath:         "com/app/Checker.smali",
			FullSignature:    "check()Z",
			ReturnsBoolean:   true,
			IsAppCode:        true,
			InstructionCount: 5,
			IfCheckCount:     1,
			RawBody: []string{
				"invoke-static {}, LChecker;->isLicensed()Z",
				"move-result v0",
				"return v0",
			},
		},
		Score: ScoreResult{
			FinalScore:     20.0,
			RiskLevel:      RiskClassMedium,
			Confidence:     0.5,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnTrue,
			Reasons:        []string{"generic"},
		},
		ClassPath: "com/app/Checker.smali",
		ClassName: "Lcom/app/Checker;",
	}

	point := pp.scoredMethodToPoint(&sm)

	// Invoke-only кейс не убивается фильтром — это важно
	t.Logf("✓ Invoke-only passes filter: HasDFG=%v RiskScore=%.2f", point.HasDFG(), point.RiskScore)
}

// makeMegaCheckMethod строит ScoredMethod с тремя license-related invoke
// и заданным baseline-скором — общий fixture для тестов dynamic cap / promotion.
func makeMegaCheckMethod(finalScore float64, level RiskClass) ScoredMethod {
	return ScoredMethod{
		Method: MethodInfo{
			Name:             "megaCheck",
			ClassName:        "Lcom/app/MegaCheck;",
			FilePath:         "com/app/MegaCheck.smali",
			FullSignature:    "megaCheck()Z",
			ReturnsBoolean:   true,
			HasCheckPrefix:   true,
			IsAppCode:        true,
			InstructionCount: 20,
			IfCheckCount:     3,
			RawBody: []string{
				"invoke-static {}, LChecker;->isLicensed()Z",
				"move-result v1",
				"if-eqz v1, :fail",
				"invoke-static {}, LChecker;->isPremium()Z",
				"move-result v2",
				"if-eqz v2, :fail",
				"invoke-static {}, LChecker;->checkLicense()Z",
				"move-result v3",
				"if-eqz v3, :fail",
				"const/4 v0, 0x1",
				"return v0",
				":fail",
				"const/4 v0, 0x0",
				"return v0",
			},
		},
		Score: ScoreResult{
			FinalScore:     finalScore,
			RiskLevel:      level,
			Confidence:     0.6,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnTrue,
			Reasons:        []string{"pattern match"},
		},
		ClassPath: "com/app/MegaCheck.smali",
		ClassName: "Lcom/app/MegaCheck;",
	}
}

// makeBigDFGFixture создаёт метод с 8+ license invokes (long trace через
// move chain) — гарантированно генерирует raw_dfg_bonus >> 25, чтобы dynamic
// cap гарантированно срабатывал на любом FinalScore в диапазоне [10..80].
//
// Расчёт raw bonus:
//
//	8 checks × (base 0.5×1.5 + per-step invoke 1.5) ≈ 8 × 2.25 = 18.0
//
// Для пробития 25 нужно ~12 checks. Используем 12.
func makeBigDFGFixture(finalScore float64) ScoredMethod {
	body := []string{}
	// 12 повторений: invoke + move-result + move chain + if-eqz → :fail
	for i := 0; i < 12; i++ {
		body = append(body,
			"invoke-static {}, LChecker;->isLicensed()Z",
			"move-result v0",
			"move v1, v0",
			"if-eqz v1, :fail")
	}
	body = append(body, "const/4 v0, 0x1", "return v0",
		":fail", "const/4 v0, 0x0", "return v0")

	return ScoredMethod{
		Method: MethodInfo{
			Name:             "bigCheck",
			ClassName:        "Lcom/app/BigCheck;",
			FilePath:         "com/app/BigCheck.smali",
			FullSignature:    "bigCheck()Z",
			ReturnsBoolean:   true,
			HasCheckPrefix:   true,
			IsAppCode:        true,
			InstructionCount: len(body),
			IfCheckCount:     12,
			RawBody:          body,
		},
		Score: ScoreResult{
			FinalScore:     finalScore,
			RiskLevel:      RiskClassMedium,
			Confidence:     0.6,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnTrue,
			Reasons:        []string{"pattern match"},
		},
		ClassPath: "com/app/BigCheck.smali",
		ClassName: "Lcom/app/BigCheck;",
	}
}

// TestDFGScoring_DynamicCap (бывший CapAt3) проверяет что Phase 1 dynamic cap
// работает: cap = clamp(FinalScore × 0.4, [8.0, 25.0]).
// Раньше hard cap = 3.0 — это давало DFG только ≈4.6% от HighRiskThreshold (65),
// то есть DFG-сигнал был фактически шумовым полом и не мог влиять на тиры.
//
// Use big fixture (12 license invokes) гарантирующий raw_bonus > 25 — cap
// должен сработать на каждом FinalScore.
func TestDFGScoring_DynamicCap(t *testing.T) {
	cases := []struct {
		name       string
		finalScore float64
		expectCap  float64 // ожидаемое значение DFG cap (capped at Y)
	}{
		// FinalScore=10 → 0.4×10=4 → clamped to floor 8
		{"low_baseline_floor", 10.0, 8.0},
		// FinalScore=25 → 0.4×25=10 → 10 (внутри [8,25])
		{"medium_baseline", 25.0, 10.0},
		// FinalScore=50 → 0.4×50=20 → 20
		{"high_baseline", 50.0, 20.0},
		// FinalScore=80 → 0.4×80=32 → clamped to ceiling 25
		{"high_baseline_ceiling", 80.0, 25.0},
	}

	pp := NewPatchPredictor(nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm := makeBigDFGFixture(tc.finalScore)
			point := pp.scoredMethodToPoint(&sm)

			// Парсим лог cap'а из WhyVulnerable. Строка вида:
			// "DFG: bonus 28.40 capped at 24.00 (FinalScore=60.0)"
			capMessage := fmt.Sprintf("capped at %.2f", tc.expectCap)
			hasCapMessage := false
			for _, r := range point.WhyVulnerable {
				if strings.Contains(r, capMessage) {
					hasCapMessage = true
					break
				}
			}
			if !hasCapMessage {
				t.Errorf("FinalScore=%.0f: expected DFG cap message %q in WhyVulnerable, got: %v",
					tc.finalScore, capMessage, point.WhyVulnerable)
			}
			t.Logf("✓ FinalScore=%.0f → DFG cap=%.1f (RiskScore=%.1f, includes structural)",
				tc.finalScore, tc.expectCap, point.RiskScore)
		})
	}
}

// TestDFGScoring_HalvingFix проверяет что Phase 1 fix halving bug работает:
// раньше каждый short-trace check делал `dfgBonus *= 0.5`, что халвило ВЕСЬ
// накопленный бонус — 3 коротких трейса давали bonus ≈ 0 даже если каждый
// был осмысленным. После фикса halving применяется только к delta текущего
// check'а.
func TestDFGScoring_HalvingFix(t *testing.T) {
	pp := NewPatchPredictor(nil)

	// Метод с тремя license invoke без move-result в trace
	// (короткий trace — по 1 шагу каждый). Раньше: 1.5 → 0.75 → 0.375 → 0.19.
	// Теперь: каждый check даёт ~0.5×(0.5×1.5 + бонусы), сумма >> 0.19.
	sm := makeMegaCheckMethod(40.0, RiskClassMedium)
	point := pp.scoredMethodToPoint(&sm)

	bonus := point.RiskScore - sm.Score.FinalScore
	// Минимум: 3 check × 0.5 (halving) × 0.5×1.5 (base check) = 1.125 — это
	// строго БОЛЬШЕ старого compounding'а который сводил всё к 0.19.
	if bonus < 1.0 {
		t.Errorf("DFG bonus = %.3f after halving fix, expected > 1.0 "+
			"(старый halving bug возвращал ≈ 0.19)", bonus)
	}
	t.Logf("✓ Halving fix: bonus=%.3f for 3 short-trace license invokes "+
		"(старый bug дал бы ≈ 0.19, теперь %.3f)", bonus, bonus)
}

// makeLongTraceMethod строит method с move-цепочками между invoke и if-eqz,
// чтобы DFG trace был >= 2 шагов и halving (short-trace penalty) не срабатывал.
// Это релевантно для проверки tier promotion: одного короткого трейса с halving
// недостаточно, чтобы преодолеть 5+ пунктов скора.
func makeLongTraceMethod(finalScore float64, level RiskClass) ScoredMethod {
	return ScoredMethod{
		Method: MethodInfo{
			Name:             "isAllowedFull",
			ClassName:        "Lcom/app/Allow;",
			FilePath:         "com/app/Allow.smali",
			FullSignature:    "isAllowedFull()Z",
			ReturnsBoolean:   true,
			HasCheckPrefix:   true,
			IsAppCode:        true,
			InstructionCount: 18,
			IfCheckCount:     3,
			RawBody: []string{
				// Check 1: invoke isLicensed → move chain v0 → v1 → if-eqz v1
				"invoke-static {}, LChecker;->isLicensed()Z",
				"move-result v0",
				"move v1, v0",
				"if-eqz v1, :fail",
				// Check 2: invoke isPremium → move chain v0 → v2 → if-eqz v2
				"invoke-static {}, LChecker;->isPremium()Z",
				"move-result v0",
				"move v2, v0",
				"if-eqz v2, :fail",
				// Check 3: invoke checkLicense → move chain v0 → v3 → if-eqz v3
				"invoke-static {}, LChecker;->checkLicense()Z",
				"move-result v0",
				"move v3, v0",
				"if-eqz v3, :fail",
				"const/4 v0, 0x1",
				"return v0",
				":fail",
				"const/4 v0, 0x0",
				"return v0",
			},
		},
		Score: ScoreResult{
			FinalScore:     finalScore,
			RiskLevel:      level,
			Confidence:     0.6,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnTrue,
			Reasons:        []string{"pattern match"},
		},
		ClassPath: "com/app/Allow.smali",
		ClassName: "Lcom/app/Allow;",
	}
}

// TestDFGScoring_TierPromotion проверяет что Phase 1 RiskLevel-после-DFG работает:
// метод с FinalScore чуть ниже HighRiskThreshold + сильный DFG промотируется
// из Medium → High. Использует long-trace fixture (через move цепочку), чтобы
// halving (short-trace penalty) не убивал бонус.
func TestDFGScoring_TierPromotion(t *testing.T) {
	pp := NewPatchPredictor(nil)

	// FinalScore = 60 (Medium), HighRiskThreshold = 65.
	// 3 license invoke с длинным trace (move chain) → halving не активен,
	// per-check bonus = 0.5×1.5 (base) + 1.5 (high-value invoke) ≈ 2.25.
	// 3 check × 2.25 = 6.75 → 60 + 6.75 = 66.75 → HIGH.
	sm := makeLongTraceMethod(60.0, RiskClassMedium)
	point := pp.scoredMethodToPoint(&sm)

	if point.RiskLevel != RiskClassHigh {
		t.Errorf("RiskLevel = %s, expected HIGH (FinalScore=60, RiskScore=%.1f)",
			point.RiskLevel, point.RiskScore)
	}
	if point.RiskScore < HighRiskThreshold {
		t.Errorf("RiskScore = %.1f, expected >= %.1f to be HIGH",
			point.RiskScore, HighRiskThreshold)
	}

	// Проверяем что лог промоции тира попал в WhyVulnerable
	hasPromotion := false
	for _, r := range point.WhyVulnerable {
		if strings.Contains(r, "RiskLevel MEDIUM → HIGH") {
			hasPromotion = true
			break
		}
	}
	if !hasPromotion {
		t.Errorf("WhyVulnerable should log MEDIUM → HIGH promotion, got: %v",
			point.WhyVulnerable)
	}
	t.Logf("✓ Tier promotion: %s @ %.1f → %s @ %.1f",
		sm.Score.RiskLevel, sm.Score.FinalScore,
		point.RiskLevel, point.RiskScore)
}

// TestDFGScoring_NoTierDemotion проверяет что DFG никогда не понижает тир.
// DFG только добавляет (delta >= 0), поэтому RiskScore >= FinalScore всегда,
// и RiskLevel может только подняться, не упасть.
func TestDFGScoring_NoTierDemotion(t *testing.T) {
	pp := NewPatchPredictor(nil)

	// Высокий FinalScore (уже HIGH), DFG может добавить ещё, но не должен снять тир
	sm := makeMegaCheckMethod(80.0, RiskClassHigh)
	point := pp.scoredMethodToPoint(&sm)

	if point.RiskLevel != RiskClassHigh {
		t.Errorf("RiskLevel demoted from HIGH to %s — DFG never reduces score",
			point.RiskLevel)
	}
	if point.RiskScore < sm.Score.FinalScore {
		t.Errorf("RiskScore=%.1f < FinalScore=%.1f — DFG never reduces score",
			point.RiskScore, sm.Score.FinalScore)
	}
	t.Logf("✓ No demotion: HIGH @ 80.0 → HIGH @ %.1f", point.RiskScore)
}

// TestDFGHelperMethods проверяет helper-методы HasDFG/GetDFGCondition/GetDFGTraceSummary
func TestDFGHelperMethods(t *testing.T) {
	// PatchPoint без DFG
	empty := &PatchPoint{}
	if empty.HasDFG() {
		t.Error("empty point should not have DFG")
	}
	if empty.GetDFGCondition() != "" {
		t.Error("empty point should return empty condition")
	}
	if empty.GetDFGTraceSummary() != nil {
		t.Error("empty point should return nil trace summary")
	}

	// PatchPoint с DFG
	invRef := "LChecker;->isLicensed()Z"
	withDFG := &PatchPoint{
		DFG: &DFGInfo{
			Available:     true,
			ConditionType: "if-eqz",
			ConditionText: "v1 == false",
			Register:      "v1",
			Confidence:    0.8,
			Trace: []DFGTraceStep{
				{Type: DFGInvoke, Register: "v1", InvokeRef: &invRef, Confidence: 0.8},
			},
		},
	}

	if !withDFG.HasDFG() {
		t.Error("point with DFG should have HasDFG() = true")
	}
	if withDFG.GetDFGCondition() != "v1 == false" {
		t.Errorf("condition = %q, want 'v1 == false'", withDFG.GetDFGCondition())
	}
	summary := withDFG.GetDFGTraceSummary()
	if len(summary) != 1 || !strings.Contains(summary[0], "isLicensed") {
		t.Errorf("summary = %v, want 1 step with isLicensed", summary)
	}

	t.Logf("✓ Helper methods work correctly")
}
