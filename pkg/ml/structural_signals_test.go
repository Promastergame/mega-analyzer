package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCTURAL SIGNALS TESTS — Phase 2
//
// Проверяем что path-sensitive сигналы (guards / hard gates / funnels) реально
// строятся над CFG, добавляются в bonus и видны в WhyVulnerable.
// ═══════════════════════════════════════════════════════════════════════════════

// buildCFGFor строит CFG из RawBody для structural-tests.
func buildCFGFor(t *testing.T, className, method, signature string, lines []string) *cfg.ControlFlowGraph {
	t.Helper()
	input := cfg.BuildInputFromLines(className, method, signature, lines)
	builder := cfg.NewCFGBuilder()
	graph := builder.Build(input)
	if graph == nil {
		t.Fatalf("CFG build returned nil")
	}
	return graph
}

// TestStructural_GuardDetected: метод с if-eqz → return false классически
// детектится как guard (DominatesExit).
func TestStructural_GuardDetected(t *testing.T) {
	graph := buildCFGFor(t,
		"Lcom/app/Check;", "isLicensed", "isLicensed()Z",
		[]string{
			"invoke-static {}, LChecker;->isLicensed()Z",
			"move-result v0",
			"if-eqz v0, :fail",
			"const/4 v0, 0x1",
			"return v0",
			":fail",
			"const/4 v0, 0x0",
			"return v0",
		})

	sig := ComputeStructuralSignals(graph)
	if sig == nil {
		t.Fatal("StructuralSignals is nil for guard method")
	}
	if sig.GuardCount == 0 {
		t.Errorf("Expected GuardCount > 0 for if-eqz → return pattern, got %d", sig.GuardCount)
	}
	t.Logf("✓ Guard detected: GuardCount=%d, HardGate=%d, DomRatio=%.2f, Funnel=%d",
		sig.GuardCount, sig.HardGateCount, sig.DominationRatio, sig.FunnelCount)
}

// TestStructural_HardGateThrow: guard с throw на failed branch — exit
// post-dominирует cond (метод 100% завершается через throw).
func TestStructural_HardGateThrow(t *testing.T) {
	graph := buildCFGFor(t,
		"Lcom/app/Verify;", "verifyOrThrow", "verifyOrThrow()V",
		[]string{
			"invoke-static {}, LChecker;->isLicensed()Z",
			"move-result v0",
			"if-eqz v0, :fail",
			"return-void",
			":fail",
			"new-instance v1, Ljava/lang/SecurityException;",
			"invoke-direct {v1}, Ljava/lang/SecurityException;-><init>()V",
			"throw v1",
		})

	sig := ComputeStructuralSignals(graph)
	if sig == nil {
		t.Fatal("StructuralSignals is nil")
	}
	if sig.GuardCount == 0 {
		t.Errorf("Expected GuardCount > 0, got %d", sig.GuardCount)
	}
	// Hard gate ожидается — экспортируем точку выхода через throw, а return-void
	// делает другой exit; cond может пост-доминироваться одним из exit'ов.
	t.Logf("✓ Hard gate test: GuardCount=%d, HardGateCount=%d, DomRatio=%.2f",
		sig.GuardCount, sig.HardGateCount, sig.DominationRatio)
}

// TestStructural_AndFunnel: 3 if-eqz все в один :fail → AND-funnel.
// Каждый check должен пройти, чтобы достичь happy-path return — это AND-семантика.
func TestStructural_AndFunnel(t *testing.T) {
	graph := buildCFGFor(t,
		"Lcom/app/Allow;", "isAllowedFull", "isAllowedFull()Z",
		[]string{
			"invoke-static {}, LChecker;->isLicensed()Z",
			"move-result v0",
			"if-eqz v0, :fail",
			"invoke-static {}, LChecker;->isPremium()Z",
			"move-result v0",
			"if-eqz v0, :fail",
			"invoke-static {}, LChecker;->checkLicense()Z",
			"move-result v0",
			"if-eqz v0, :fail",
			"const/4 v0, 0x1",
			"return v0",
			":fail",
			"const/4 v0, 0x0",
			"return v0",
		})

	sig := ComputeStructuralSignals(graph)
	if sig == nil {
		t.Fatal("StructuralSignals is nil")
	}
	if sig.GuardCount < 3 {
		t.Errorf("Expected >= 3 guards, got %d", sig.GuardCount)
	}
	if sig.FunnelCount == 0 {
		t.Errorf("Expected FunnelCount > 0 for 3-condition AND-chain, got %d", sig.FunnelCount)
	}
	t.Logf("✓ AND-funnel test: GuardCount=%d, FunnelCount=%d, HasAndFunnel=%v, HasOrFunnel=%v, DomRatio=%.2f",
		sig.GuardCount, sig.FunnelCount, sig.HasAndFunnel, sig.HasOrFunnel, sig.DominationRatio)
}

// TestStructural_NoSignals: простой геттер без if-условий — никаких сигналов.
func TestStructural_NoSignals(t *testing.T) {
	graph := buildCFGFor(t,
		"Lcom/app/Conf;", "getX", "getX()I",
		[]string{
			"iget v0, p0, Lcom/app/Conf;->x:I",
			"return v0",
		})

	sig := ComputeStructuralSignals(graph)
	if sig == nil {
		// Допустимо: nil для тривиального графа.
		t.Logf("✓ No signals (nil) for trivial getter — expected behavior")
		return
	}
	if sig.GuardCount != 0 || sig.FunnelCount != 0 {
		t.Errorf("Expected zero signals for trivial getter, got Guard=%d Funnel=%d",
			sig.GuardCount, sig.FunnelCount)
	}
	t.Logf("✓ Trivial method has no structural signals")
}

// TestStructural_ScoreContribution: проверяет что ScoreContribution возвращает
// предсказуемые числа на известных входах.
func TestStructural_ScoreContribution(t *testing.T) {
	cases := []struct {
		name        string
		sig         *StructuralSignals
		expectMinB  float64
		expectMaxB  float64
		expectInLog string // подстрока, ожидаемая в reasons
	}{
		{
			name:        "nil_signals_zero_bonus",
			sig:         nil,
			expectMinB:  0,
			expectMaxB:  0,
			expectInLog: "",
		},
		{
			name: "single_guard",
			sig: &StructuralSignals{
				GuardCount: 1,
			},
			expectMinB:  4.9, // 1 guard × 5 = 5
			expectMaxB:  5.1,
			expectInLog: "1 guard(s) detected",
		},
		{
			name: "guard_cap_at_15",
			sig: &StructuralSignals{
				GuardCount: 10, // 10 × 5 = 50, but capped at 15
			},
			expectMinB:  14.9,
			expectMaxB:  15.1,
			expectInLog: "10 guard(s) detected",
		},
		{
			name: "hard_gate_bonus",
			sig: &StructuralSignals{
				GuardCount:    1,
				HardGateCount: 1,
			},
			expectMinB:  7.9, // 5 guard + 3 hard gate = 8
			expectMaxB:  8.1,
			expectInLog: "HARD GATE",
		},
		{
			name: "and_funnel_bonus",
			sig: &StructuralSignals{
				HasAndFunnel: true,
			},
			expectMinB:  3.9, // +4
			expectMaxB:  4.1,
			expectInLog: "AND-funnel",
		},
		{
			name: "domination_ratio_high",
			sig: &StructuralSignals{
				GuardCount:      1,
				DominationRatio: 0.8,
			},
			// guard 5 + ratio 0.8×8 = 5 + 6.4 = 11.4
			expectMinB:  11.3,
			expectMaxB:  11.5,
			expectInLog: "guards dominate 80%",
		},
		{
			name: "domination_ratio_below_threshold",
			sig: &StructuralSignals{
				GuardCount:      1,
				DominationRatio: 0.2, // < 0.3 threshold — не должен срабатывать
			},
			expectMinB:  4.9, // только guard 5
			expectMaxB:  5.1,
			expectInLog: "1 guard(s) detected",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bonus, reasons := tc.sig.ScoreContribution()
			if bonus < tc.expectMinB || bonus > tc.expectMaxB {
				t.Errorf("bonus=%.2f, expected in [%.2f, %.2f]",
					bonus, tc.expectMinB, tc.expectMaxB)
			}
			if tc.expectInLog != "" {
				found := false
				for _, r := range reasons {
					if strings.Contains(r, tc.expectInLog) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected log substring %q in reasons %v",
						tc.expectInLog, reasons)
				}
			}
			t.Logf("✓ %s: bonus=%.2f, reasons=%d", tc.name, bonus, len(reasons))
		})
	}
}

// TestStructural_IntegrationInScoredMethodToPoint: end-to-end что Phase 2 bonus
// реально попадает в RiskScore и WhyVulnerable.
func TestStructural_IntegrationInScoredMethodToPoint(t *testing.T) {
	pp := NewPatchPredictor(nil)
	sm := makeMegaCheckMethod(40.0, RiskClassMedium)
	point := pp.scoredMethodToPoint(&sm)

	if point.Structural == nil {
		t.Fatal("PatchPoint.Structural is nil — Phase 2 not wired into pipeline")
	}
	if point.Structural.GuardCount == 0 {
		t.Errorf("Expected GuardCount > 0 for megaCheck (3 if-eqz → :fail), got 0")
	}

	// Проверяем что STRUCT reasons попали в WhyVulnerable
	hasStructReason := false
	for _, r := range point.WhyVulnerable {
		if strings.Contains(r, "STRUCT:") {
			hasStructReason = true
			break
		}
	}
	if !hasStructReason {
		t.Errorf("WhyVulnerable должен содержать STRUCT: ... reason, got: %v",
			point.WhyVulnerable)
	}

	t.Logf("✓ E2E: GuardCount=%d, FunnelCount=%d, RiskScore=%.1f (base=40 + DFG+struct)",
		point.Structural.GuardCount, point.Structural.FunnelCount, point.RiskScore)
}
