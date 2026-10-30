package ml

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH VALUE TESTS — Phase 3
//
// Проверяем что:
//   1. ComputePatchValue корректно работает на нулевых/неполных данных
//   2. CrackingImpact / BypassCost корректно реагируют на Structural флаги
//   3. DetectionRisk поднимается при наличии anti-tamper API
//   4. BreakageRisk поднимается при несовместимости return-type/strategy
//   5. Tier классификация (TOP/GOOD/OK/LOW)
//   6. Sorting prediction'а по PatchValue
// ═══════════════════════════════════════════════════════════════════════════════

func TestPatchValue_NilSafety(t *testing.T) {
	if pv := ComputePatchValue(nil, nil); pv != nil {
		t.Errorf("ComputePatchValue(nil, nil) = %v, want nil", pv)
	}

	// Точка без Method — должно работать с дефолтами.
	p := &PatchPoint{RiskScore: 50.0}
	pv := ComputePatchValue(p, nil)
	if pv == nil {
		t.Fatal("ComputePatchValue with nil Method returned nil")
	}
	if pv.RiskScoreInput != 50.0 {
		t.Errorf("RiskScoreInput = %.1f, want 50.0", pv.RiskScoreInput)
	}
}

func TestPatchValue_HardGate(t *testing.T) {
	// HARD GATE = guards с post-domination. CrackingImpact=1.0, Cost=1.0
	p := &PatchPoint{
		RiskScore: 75.0,
		Structural: &StructuralSignals{
			GuardCount:    1,
			HardGateCount: 1,
		},
	}
	mi := &MethodInfo{ReturnType: "Z"}
	pv := ComputePatchValue(p, mi)

	if pv.CrackingImpact != 1.0 {
		t.Errorf("HARD GATE expected Impact=1.0, got %.2f", pv.CrackingImpact)
	}
	if pv.BypassCost != 1.0 {
		t.Errorf("HARD GATE expected Cost=1.0, got %.2f", pv.BypassCost)
	}
	if !strings.Contains(pv.ImpactReason, "HARD GATE") {
		t.Errorf("ImpactReason should mention HARD GATE, got %q", pv.ImpactReason)
	}
	t.Logf("✓ HARD GATE: %s", pv.Explain())
}

func TestPatchValue_AndFunnelEntry(t *testing.T) {
	// AND-funnel: 3 guards + HasAndFunnel → один patch entry ломает chain.
	p := &PatchPoint{
		RiskScore: 60.0,
		Structural: &StructuralSignals{
			GuardCount:   3,
			HasAndFunnel: true,
		},
	}
	mi := &MethodInfo{ReturnType: "Z"}
	pv := ComputePatchValue(p, mi)

	if pv.CrackingImpact != 1.0 {
		t.Errorf("AND-funnel entry expected Impact=1.0, got %.2f", pv.CrackingImpact)
	}
	if pv.BypassCost != 1.0 {
		t.Errorf("AND-funnel entry expected Cost=1.0 (single entry-patch), got %.2f", pv.BypassCost)
	}
	if !strings.Contains(pv.ImpactReason, "AND-funnel") {
		t.Errorf("ImpactReason should mention AND-funnel, got %q", pv.ImpactReason)
	}
	t.Logf("✓ AND-funnel: %s", pv.Explain())
}

func TestPatchValue_OrFunnelDilution(t *testing.T) {
	// OR-funnel с 4 guards: каждый = 1/4 пути, нужно патчить 4.
	p := &PatchPoint{
		RiskScore: 60.0,
		Structural: &StructuralSignals{
			GuardCount:   4,
			HasOrFunnel:  true,
			HasAndFunnel: false,
			FunnelCount:  1,
		},
	}
	mi := &MethodInfo{ReturnType: "Z"}
	pv := ComputePatchValue(p, mi)

	if pv.CrackingImpact != 0.25 {
		t.Errorf("OR-funnel 1/4 expected Impact=0.25, got %.2f", pv.CrackingImpact)
	}
	if pv.BypassCost != 4.0 {
		t.Errorf("OR-funnel 4-paths expected Cost=4.0, got %.2f", pv.BypassCost)
	}
	t.Logf("✓ OR-funnel dilution: %s", pv.Explain())
}

func TestPatchValue_DecoyClassification(t *testing.T) {
	// Decoy: высокий RiskScore (от pattern match), но нет Structural.
	// Expected: low CrackingImpact (0.3) → low PatchValue.
	p := &PatchPoint{
		RiskScore:  80.0,
		Structural: nil, // нет структурных сигналов
	}
	mi := &MethodInfo{ReturnType: "Z"}
	pv := ComputePatchValue(p, mi)

	// Когда Structural=nil, computeImpactAndCost возвращает baseline (0.5).
	// А когда Structural есть, но guards=0 — impact=0.3 (decoy).
	if pv.CrackingImpact > 0.6 {
		t.Errorf("No-structural expected low Impact (≤ 0.5), got %.2f", pv.CrackingImpact)
	}
	t.Logf("✓ Decoy/no-structural: %s", pv.Explain())
}

func TestPatchValue_DetectionRisk_PlayIntegrity(t *testing.T) {
	// Anti-tamper indicator: PlayIntegrity API в Calls → Detection=2.5
	p := &PatchPoint{
		RiskScore: 70.0,
		Structural: &StructuralSignals{
			GuardCount:    1,
			HardGateCount: 1,
		},
	}
	mi := &MethodInfo{
		ReturnType: "Z",
		Calls: []CallInfo{
			{FullCall: "Lcom/google/android/play/core/integrity/IntegrityManager;->requestIntegrityToken"},
		},
	}
	pv := ComputePatchValue(p, mi)

	if pv.DetectionRisk < 2.0 {
		t.Errorf("PlayIntegrity should give DetectionRisk ≥ 2.0, got %.2f", pv.DetectionRisk)
	}
	if !strings.Contains(pv.DetectionReason, "PlayIntegrity") {
		t.Errorf("DetectionReason should mention PlayIntegrity, got %q", pv.DetectionReason)
	}
	t.Logf("✓ PlayIntegrity proximity: %s", pv.Explain())
}

func TestPatchValue_BreakageRisk_TypeMismatch(t *testing.T) {
	// SuggestedPatch=PatchReturnTrue, но method returns int → BreakageRisk=2.0
	p := &PatchPoint{
		RiskScore:      70.0,
		SuggestedPatch: PatchReturnTrue,
		Structural: &StructuralSignals{
			GuardCount:    1,
			HardGateCount: 1,
		},
	}
	mi := &MethodInfo{ReturnType: "I"} // не Z!
	pv := ComputePatchValue(p, mi)

	if pv.BreakageRisk < 1.5 {
		t.Errorf("type mismatch should give BreakageRisk ≥ 1.5, got %.2f", pv.BreakageRisk)
	}
	if !strings.Contains(pv.BreakageReason, "boolean") {
		t.Errorf("BreakageReason should mention boolean mismatch, got %q", pv.BreakageReason)
	}
	t.Logf("✓ Type mismatch: %s", pv.Explain())
}

func TestPatchValue_Tier(t *testing.T) {
	cases := []struct {
		value    float64
		expected string
	}{
		{0.5, "⚠ LOW"},
		{2.5, "🥉 OK"},
		{5.0, "🥈 GOOD"},
		{8.5, "🥇 TOP"},
	}
	for _, tc := range cases {
		b := &PatchValueBreakdown{Value: tc.value}
		got := b.Tier()
		if got != tc.expected {
			t.Errorf("Value=%.1f: tier=%q, want %q", tc.value, got, tc.expected)
		}
	}
	// nil safety
	var nilB *PatchValueBreakdown
	if got := nilB.Tier(); got != "?" {
		t.Errorf("nil tier = %q, want '?'", got)
	}
}

func TestPatchValue_TopGate_FullScenario(t *testing.T) {
	// Идеальный сценарий: HARD GATE, no anti-tamper, type compatible.
	// PatchValue = 80×1.0 / (1.0 × 1.0 × 1.0) = 80, нормализованный /10 = 8.0
	p := &PatchPoint{
		RiskScore:      80.0,
		SuggestedPatch: PatchReturnTrue,
		Structural: &StructuralSignals{
			GuardCount:    1,
			HardGateCount: 1,
		},
	}
	mi := &MethodInfo{ReturnType: "Z"}
	pv := ComputePatchValue(p, mi)

	if pv.Value < 7.0 {
		t.Errorf("Top scenario PatchValue=%.2f, expected ≥ 7.0 (TOP tier)", pv.Value)
	}
	if pv.Tier() != "🥇 TOP" {
		t.Errorf("Tier=%q, want '🥇 TOP'", pv.Tier())
	}
	t.Logf("✓ TOP scenario: %s", pv.Explain())
}

func TestPatchValue_E2EPriorityOrder(t *testing.T) {
	// E2E: создаём 3 метода — top (HARD GATE), mid (soft guard),
	// low (only pattern match, no structural). Проверяем что после
	// scoredMethodToPoint и сортировки (если бы делалось через buildPrediction)
	// они расположены TOP > MID > LOW.

	pp := NewPatchPredictor(nil)

	// TOP: HARD GATE через throw (post-domination)
	smTop := ScoredMethod{
		Method: MethodInfo{
			Name:             "verifyOrThrow",
			ClassName:        "Lcom/app/HardGate;",
			FilePath:         "com/app/HardGate.smali",
			FullSignature:    "verifyOrThrow()V",
			ReturnType:       "V",
			ReturnsVoid:      true,
			IsAppCode:        true,
			InstructionCount: 12,
			IfCheckCount:     1,
			RawBody: []string{
				"invoke-static {}, LChecker;->isLicensed()Z",
				"move-result v0",
				"if-eqz v0, :fail",
				"return-void",
				":fail",
				"new-instance v1, Ljava/lang/SecurityException;",
				"invoke-direct {v1}, Ljava/lang/SecurityException;-><init>()V",
				"throw v1",
			},
		},
		Score: ScoreResult{
			FinalScore:     70.0,
			RiskLevel:      RiskClassHigh,
			Confidence:     0.8,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnVoid,
			Reasons:        []string{"pattern: license"},
		},
		ClassPath: "com/app/HardGate.smali",
		ClassName: "Lcom/app/HardGate;",
	}

	// LOW: высокий FinalScore по pattern match, но без structural
	smLow := ScoredMethod{
		Method: MethodInfo{
			Name:             "noStructure",
			ClassName:        "Lcom/app/Decoy;",
			FilePath:         "com/app/Decoy.smali",
			FullSignature:    "noStructure()Z",
			ReturnType:       "Z",
			ReturnsBoolean:   true,
			IsAppCode:        true,
			InstructionCount: 3,
			IfCheckCount:     0,
			RawBody: []string{
				"const/4 v0, 0x1",
				"return v0",
			},
		},
		Score: ScoreResult{
			FinalScore:     65.0,
			RiskLevel:      RiskClassHigh,
			Confidence:     0.7,
			PatchCategory:  PatchCatLicense,
			SuggestedPatch: PatchReturnTrue,
			Reasons:        []string{"name match"},
		},
		ClassPath: "com/app/Decoy.smali",
		ClassName: "Lcom/app/Decoy;",
	}

	pTop := pp.scoredMethodToPoint(&smTop)
	pLow := pp.scoredMethodToPoint(&smLow)

	if pTop.PatchValue == nil || pLow.PatchValue == nil {
		t.Fatal("PatchValue not populated")
	}

	t.Logf("TOP point: %s", pTop.PatchValue.Explain())
	t.Logf("LOW point: %s", pLow.PatchValue.Explain())

	// HARD GATE > no-structural в любом разумном случае.
	if pTop.PatchValue.Value <= pLow.PatchValue.Value {
		t.Errorf("Expected HARD GATE PatchValue > no-structural; top=%.2f low=%.2f",
			pTop.PatchValue.Value, pLow.PatchValue.Value)
	}
}
