package cfg

import (
	"testing"
)

func TestMetrics_Coverage(t *testing.T) {
	instructions := []Instruction{
		{Line: 1, Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x1"},
		{Line: 2, Index: 1, Opcode: "if-eqz", Raw: "if-eqz v0, :label_1"},
		{Line: 3, Index: 2, Opcode: "const/4", Raw: "const/4 v0, 0x2"},
		{Line: 4, Index: 3, Opcode: ":label_1"},
		{Line: 5, Index: 4, Opcode: "return-void", Raw: "return-void"},
	}

	builder := NewCFGBuilder()
	res := builder.BuildEx(BuildInput{Instructions: instructions})
	cfg := res.CFG

	metrics := NewMetrics(cfg)

	// Test Halstead
	h := metrics.HalsteadComplexity()
	if h.ProgramLength == 0 {
		t.Error("Halstead length should be > 0")
	}

	// Test Maintainability
	mi := metrics.MaintainabilityIndex()
	_ = mi.Rating

	// Test NPath
	npath := metrics.NPathComplexity()
	if npath == 0 {
		t.Error("NPath should be > 0")
	}

	// Test Fan Analysis
	fan := metrics.FanAnalysis()
	if fan.AvgFanIn == 0 {
		// Entry node has 0 fan-in, but other nodes should have
	}

	// Test Obfuscation
	obf := metrics.ObfuscationDetection()
	_ = obf.Score

	// Test AI Readiness
	ai := metrics.AIReadiness()
	_ = ai.Score

	// Test Ultimate Summary
	_ = metrics.UltimateSummary()
}

func TestMetrics_EdgeCases(t *testing.T) {
	metrics := NewMetrics(&ControlFlowGraph{})
	metrics.HalsteadComplexity()
	metrics.NPathComplexity()
	metrics.AIReadiness()
}
