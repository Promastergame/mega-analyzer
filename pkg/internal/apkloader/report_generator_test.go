package apkloader

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT GENERATOR TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestReportGenerator_BasicReport tests basic report generation.
func TestReportGenerator_BasicReport(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	if report == nil {
		t.Fatalf("Expected report, got nil")
	}
	if report.Title == "" {
		t.Errorf("Expected report title, got empty")
	}

	if report.RecoveryStats.VariablesTotal == 0 {
		t.Errorf("Expected variables total > 0, got %d", report.RecoveryStats.VariablesTotal)
	}
}

// TestReportGenerator_RecoveryStatistics tests recovery statistics collection.
func TestReportGenerator_RecoveryStatistics(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 2},
		{Kind: MIR_ADD, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	stats := rg.collectRecoveryStatistics()

	if stats.VariablesTotal == 0 {
		t.Errorf("Expected variables total > 0, got %d", stats.VariablesTotal)
	}

	if stats.VariableRecoveryRate < 0 || stats.VariableRecoveryRate > 100 {
		t.Errorf("Expected recovery rate 0-100, got %.1f", stats.VariableRecoveryRate)
	}
}

// TestReportGenerator_ComplexityMetrics tests complexity metrics calculation.
func TestReportGenerator_ComplexityMetrics(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Src1: 0, Imm: 3},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	metrics := rg.calculateComplexityMetrics()

	if metrics.OriginalInstructionCount == 0 {
		t.Errorf("Expected original instruction count > 0, got %d", metrics.OriginalInstructionCount)
	}

	if metrics.OriginalCyclomaticComplexity < 1 {
		t.Errorf("Expected cyclomatic complexity >= 1, got %d", metrics.OriginalCyclomaticComplexity)
	}

	if metrics.ComplexityReductionPercent < 0 || metrics.ComplexityReductionPercent > 100 {
		t.Errorf("Expected complexity reduction 0-100, got %.1f", metrics.ComplexityReductionPercent)
	}
}

// TestReportGenerator_CyclomaticComplexity tests cyclomatic complexity calculation.
func TestReportGenerator_CyclomaticComplexity(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Src1: 0, Imm: 3},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	rg := NewReportGenerator(cfg, ssa, nil, nil, nil, nil, nil, nil, nil)
	complexity := rg.calculateCyclomaticComplexity()

	if complexity < 1 {
		t.Errorf("Expected cyclomatic complexity >= 1, got %d", complexity)
	}
}

// TestReportGenerator_ConfidenceDistribution tests confidence distribution analysis.
func TestReportGenerator_ConfidenceDistribution(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	rg := NewReportGenerator(cfg, ssa, vr, nil, nil, nil, nil, nil, nil)
	dist := rg.analyzeVariableConfidenceDistribution()

	if dist.Total < 0 {
		t.Errorf("Expected total >= 0, got %d", dist.Total)
	}

	if dist.VeryHigh < 0 || dist.High < 0 || dist.Medium < 0 || dist.Low < 0 || dist.VeryLow < 0 {
		t.Errorf("Expected non-negative confidence counts")
	}

	if dist.Total > 0 {
		sum := dist.VeryHigh + dist.High + dist.Medium + dist.Low + dist.VeryLow
		if sum != dist.Total {
			t.Errorf("Expected sum of confidence counts to equal total, got %d != %d", sum, dist.Total)
		}
	}
}

// TestReportGenerator_Recommendations tests recommendation generation.
func TestReportGenerator_Recommendations(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	recommendations := rg.generateRecommendations()

	if len(recommendations) == 0 {
		t.Errorf("Expected recommendations, got none")
	}

	for _, rec := range recommendations {
		if rec.Priority == "" {
			t.Errorf("Expected recommendation priority, got empty")
		}

		if rec.Category == "" {
			t.Errorf("Expected recommendation category, got empty")
		}

		if rec.Description == "" {
			t.Errorf("Expected recommendation description, got empty")
		}

		if rec.Action == "" {
			t.Errorf("Expected recommendation action, got empty")
		}

		// Validate priority
		if rec.Priority != "high" && rec.Priority != "medium" && rec.Priority != "low" {
			t.Errorf("Expected priority to be high/medium/low, got %s", rec.Priority)
		}
	}
}

// TestReportGenerator_ObfuscationTechniques tests obfuscation technique detection.
func TestReportGenerator_ObfuscationTechniques(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	techniques := rg.detectObfuscationTechniques()

	for _, technique := range techniques {
		if technique.Name == "" {
			t.Errorf("Expected technique name, got empty")
		}

		if technique.Description == "" {
			t.Errorf("Expected technique description, got empty")
		}

		if technique.Occurrences < 0 {
			t.Errorf("Expected occurrences >= 0, got %d", technique.Occurrences)
		}

		if technique.Coverage < 0 || technique.Coverage > 100 {
			t.Errorf("Expected coverage 0-100, got %.1f", technique.Coverage)
		}

		if technique.Severity != "low" && technique.Severity != "medium" && technique.Severity != "high" {
			t.Errorf("Expected severity to be low/medium/high, got %s", technique.Severity)
		}
	}
}

// TestReportGenerator_FormatAsText tests text formatting.
func TestReportGenerator_FormatAsText(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	text := report.FormatAsText()

	if text == "" {
		t.Errorf("Expected formatted text, got empty")
	}

	if !strings.Contains(text, "DEOBFUSCATION") {
		t.Errorf("Expected formatted text to contain 'DEOBFUSCATION'")
	}

	if !strings.Contains(text, "RECOVERY") {
		t.Errorf("Expected formatted text to contain 'RECOVERY'")
	}
}

// TestReportGenerator_FormatAsJSON tests JSON formatting.
func TestReportGenerator_FormatAsJSON(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	json := report.FormatAsJSON()

	if json == "" {
		t.Errorf("Expected formatted JSON, got empty")
	}

	if !strings.Contains(json, "{") || !strings.Contains(json, "}") {
		t.Errorf("Expected formatted JSON to contain braces")
	}

	if !strings.Contains(json, "title") {
		t.Errorf("Expected formatted JSON to contain 'title'")
	}
}

// TestReportGenerator_GetSummary tests summary retrieval.
func TestReportGenerator_GetSummary(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	summary := report.GetSummary()

	if summary == "" {
		t.Errorf("Expected summary, got empty")
	}

	if !strings.Contains(summary, "SUMMARY") {
		t.Errorf("Expected summary to contain 'SUMMARY'")
	}
}

// TestReportGenerator_GetDetailedReport tests detailed report retrieval.
func TestReportGenerator_GetDetailedReport(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	detailed := report.GetDetailedReport()

	if detailed == "" {
		t.Errorf("Expected detailed report, got empty")
	}

	if !strings.Contains(detailed, "DETAILED") {
		t.Errorf("Expected detailed report to contain 'DETAILED'")
	}
}

// TestReportGenerator_GetRecoveryStatistics tests recovery statistics retrieval.
func TestReportGenerator_GetRecoveryStatistics(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	stats := report.GetRecoveryStatistics()

	if stats.VariablesTotal == 0 {
		t.Errorf("Expected variables total > 0, got %d", stats.VariablesTotal)
	}
}

// TestReportGenerator_GetComplexityMetrics tests complexity metrics retrieval.
func TestReportGenerator_GetComplexityMetrics(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	metrics := report.GetComplexityMetrics()

	if metrics.OriginalInstructionCount == 0 {
		t.Errorf("Expected original instruction count > 0, got %d", metrics.OriginalInstructionCount)
	}
}

// TestReportGenerator_GetObfuscationTechniques tests obfuscation techniques retrieval.
func TestReportGenerator_GetObfuscationTechniques(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	techniques := report.GetObfuscationTechniques()

	if techniques == nil {
		t.Errorf("Expected obfuscation techniques, got nil")
	}
}

// TestReportGenerator_GetRecommendations tests recommendations retrieval.
func TestReportGenerator_GetRecommendations(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	recommendations := report.GetRecommendations()

	if len(recommendations) == 0 {
		t.Errorf("Expected recommendations, got none")
	}
}

// TestReportGenerator_EmptyCFG tests report generation with empty CFG.
func TestReportGenerator_EmptyCFG(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}

	rg := NewReportGenerator(cfg, nil, nil, nil, nil, nil, nil, nil, nil)
	report := rg.GenerateReport()

	if report == nil {
		t.Fatalf("Expected report, got nil")
	}
	if report.ComplexityMetrics.OriginalInstructionCount != 0 {
		t.Errorf("Expected 0 instructions for empty CFG, got %d", report.ComplexityMetrics.OriginalInstructionCount)
	}
}

// TestReportGenerator_Coverage tests coverage calculation.
func TestReportGenerator_Coverage(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	rg := NewReportGenerator(cfg, ssa, nil, nil, nil, nil, nil, nil, nil)

	coverage := rg.calculateCoverage(1)

	if coverage < 0 || coverage > 100 {
		t.Errorf("Expected coverage 0-100, got %.1f", coverage)
	}
}

// TestReportGenerator_MethodConfidenceDistribution tests method confidence distribution.
func TestReportGenerator_MethodConfidenceDistribution(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	rg := NewReportGenerator(cfg, ssa, nil, nil, nil, nil, nil, nil, nil)
	dist := rg.analyzeMethodConfidenceDistribution()

	if dist.Total < 0 {
		t.Errorf("Expected total >= 0, got %d", dist.Total)
	}
}

// TestReportGenerator_ComplexReport tests report generation with all components.
func TestReportGenerator_ComplexReport(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 2},
		{Kind: MIR_IF, Offset: 2, Src1: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 3, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: 6},
		{Kind: MIR_SUB, Offset: 5, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 6, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	cp := ConstantPropagation(cfg, ssa)
	dca := AnalyzeDeadCode(cfg, ssa)

	rg := NewReportGenerator(cfg, ssa, vr, cp, dca, nil, nil, nil, nil)
	report := rg.GenerateReport()

	if report == nil {
		t.Fatalf("Expected report, got nil")
	}
	if report.ComplexityMetrics.OriginalCyclomaticComplexity < 1 {
		t.Errorf("Expected cyclomatic complexity >= 1, got %d", report.ComplexityMetrics.OriginalCyclomaticComplexity)
	}

	if len(report.Recommendations) == 0 {
		t.Errorf("Expected recommendations, got none")
	}
}
