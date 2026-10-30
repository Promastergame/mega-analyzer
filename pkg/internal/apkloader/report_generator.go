package apkloader

import (
	"fmt"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS REPORT GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Generates comprehensive analysis reports summarizing recovery results,
// complexity reduction metrics, detected obfuscation techniques, and recommendations.

// RecoveryStatistics contains statistics about recovered names.
type RecoveryStatistics struct {
	VariablesRecovered       int
	VariablesTotal           int
	VariableRecoveryRate     float64
	MethodsRecovered         int
	MethodsTotal             int
	MethodRecoveryRate       float64
	ConstantsRecovered       int
	ConstantsTotal           int
	ConstantRecoveryRate     float64
	ReflectionResolved       int
	ReflectionTotal          int
	ReflectionResolutionRate float64
}

// ComplexityMetrics contains code complexity reduction metrics.
type ComplexityMetrics struct {
	OriginalCyclomaticComplexity int
	ReducedCyclomaticComplexity  int
	ComplexityReductionPercent   float64
	OriginalInstructionCount     int
	ReducedInstructionCount      int
	InstructionReductionPercent  float64
	UnreachableBlocksRemoved     int
	DeadAssignmentsRemoved       int
	OpaquePredicatesRemoved      int
	LoopsReconstructed           int
	ExceptionHandlersStructured  int
}

// ObfuscationTechnique represents a detected obfuscation technique.
type ObfuscationTechnique struct {
	Name        string
	Description string
	Occurrences int
	Coverage    float64 // percentage of code affected
	Severity    string  // "low", "medium", "high"
}

// ConfidenceDistribution represents the distribution of confidence scores.
type ConfidenceDistribution struct {
	VeryHigh int // 80-100
	High     int // 60-79
	Medium   int // 40-59
	Low      int // 20-39
	VeryLow  int // 0-19
	Total    int
}

// Recommendation represents a recommendation for further analysis.
type Recommendation struct {
	Priority    string // "high", "medium", "low"
	Category    string // "variable_recovery", "method_recovery", "reflection", etc.
	Description string
	Action      string
}

// AnalysisReport is the complete analysis report.
type AnalysisReport struct {
	Title                          string
	Timestamp                      string
	RecoveryStats                  RecoveryStatistics
	ComplexityMetrics              ComplexityMetrics
	ObfuscationTechniques          []ObfuscationTechnique
	VariableConfidenceDistribution ConfidenceDistribution
	MethodConfidenceDistribution   ConfidenceDistribution
	Recommendations                []Recommendation
	SummaryText                    string
	DetailedText                   string
}

// ReportGenerator generates analysis reports.
type ReportGenerator struct {
	CFG                     *CFG
	SSA                     *SSAForm
	VariableRecovery        *VariableRecovery
	ConstantPropagation     *PropagationResult
	DeadCodeAnalysis        *DeadCodeAnalysis
	OpaquePredicateAnalysis *OpaquePredicateAnalysis
	LoopAnalysis            *LoopAnalysis
	ExceptionStructuring    *ExceptionStructuringResult
	PatternSimplification   *PatternSimplificationResult
}

// NewReportGenerator creates a new report generator.
func NewReportGenerator(
	cfg *CFG,
	ssa *SSAForm,
	vr *VariableRecovery,
	cp *PropagationResult,
	dca *DeadCodeAnalysis,
	opa *OpaquePredicateAnalysis,
	la *LoopAnalysis,
	es *ExceptionStructuringResult,
	ps *PatternSimplificationResult,
) *ReportGenerator {
	return &ReportGenerator{
		CFG:                     cfg,
		SSA:                     ssa,
		VariableRecovery:        vr,
		ConstantPropagation:     cp,
		DeadCodeAnalysis:        dca,
		OpaquePredicateAnalysis: opa,
		LoopAnalysis:            la,
		ExceptionStructuring:    es,
		PatternSimplification:   ps,
	}
}

// GenerateReport generates a comprehensive analysis report.
func (rg *ReportGenerator) GenerateReport() *AnalysisReport {
	report := &AnalysisReport{
		Title:                          "Deobfuscation Pipeline Analysis Report",
		Timestamp:                      fmt.Sprintf("%v", "2024-01-01"), // Would use actual timestamp
		RecoveryStats:                  rg.collectRecoveryStatistics(),
		ComplexityMetrics:              rg.calculateComplexityMetrics(),
		ObfuscationTechniques:          rg.detectObfuscationTechniques(),
		VariableConfidenceDistribution: rg.analyzeVariableConfidenceDistribution(),
		MethodConfidenceDistribution:   rg.analyzeMethodConfidenceDistribution(),
		Recommendations:                rg.generateRecommendations(),
	}

	report.SummaryText = rg.generateSummary(report)
	report.DetailedText = rg.generateDetailedReport(report)

	return report
}

// collectRecoveryStatistics collects recovery statistics from all analysis passes.
func (rg *ReportGenerator) collectRecoveryStatistics() RecoveryStatistics {
	stats := RecoveryStatistics{}

	// Variable recovery statistics
	if rg.VariableRecovery != nil {
		stats.VariablesRecovered = rg.VariableRecovery.RecoveryCount()
		if rg.SSA != nil {
			stats.VariablesTotal = rg.SSA.VariableCount()
		}
		if stats.VariablesTotal > 0 {
			stats.VariableRecoveryRate = float64(stats.VariablesRecovered) / float64(stats.VariablesTotal) * 100
		}
	}

	// Constant recovery statistics
	if rg.ConstantPropagation != nil {
		stats.ConstantsRecovered = len(rg.ConstantPropagation.Constants)
		if rg.SSA != nil {
			stats.ConstantsTotal = rg.SSA.VariableCount()
		}
		if stats.ConstantsTotal > 0 {
			stats.ConstantRecoveryRate = float64(stats.ConstantsRecovered) / float64(stats.ConstantsTotal) * 100
		}
	}

	return stats
}

// calculateComplexityMetrics calculates code complexity reduction metrics.
func (rg *ReportGenerator) calculateComplexityMetrics() ComplexityMetrics {
	metrics := ComplexityMetrics{}

	// Calculate original instruction count
	if rg.CFG != nil {
		for _, block := range rg.CFG.Blocks {
			metrics.OriginalInstructionCount += len(block.Insns)
		}
	}

	// Calculate reduced instruction count (after dead code elimination)
	metrics.ReducedInstructionCount = metrics.OriginalInstructionCount
	if rg.DeadCodeAnalysis != nil {
		metrics.UnreachableBlocksRemoved = rg.DeadCodeAnalysis.UnreachableBlockCount()
		metrics.DeadAssignmentsRemoved = rg.DeadCodeAnalysis.DeadAssignmentCount()

		// Estimate instruction reduction
		for _, deadAssignment := range rg.DeadCodeAnalysis.DeadAssignments {
			if deadAssignment.Block != nil && deadAssignment.Insn >= 0 && deadAssignment.Insn < len(deadAssignment.Block.Insns) {
				metrics.ReducedInstructionCount--
			}
		}
	}

	// Calculate cyclomatic complexity
	metrics.OriginalCyclomaticComplexity = rg.calculateCyclomaticComplexity()
	metrics.ReducedCyclomaticComplexity = metrics.OriginalCyclomaticComplexity

	// Account for opaque predicate removal
	if rg.OpaquePredicateAnalysis != nil {
		metrics.OpaquePredicatesRemoved = len(rg.OpaquePredicateAnalysis.AlwaysTrue) + len(rg.OpaquePredicateAnalysis.AlwaysFalse)
		metrics.ReducedCyclomaticComplexity -= metrics.OpaquePredicatesRemoved
	}

	// Account for loop reconstruction
	if rg.LoopAnalysis != nil {
		metrics.LoopsReconstructed = len(rg.LoopAnalysis.Loops)
	}

	// Account for exception structuring
	if rg.ExceptionStructuring != nil {
		metrics.ExceptionHandlersStructured = len(rg.ExceptionStructuring.Handlers)
	}

	// Calculate reduction percentages
	if metrics.OriginalInstructionCount > 0 {
		metrics.InstructionReductionPercent = float64(metrics.OriginalInstructionCount-metrics.ReducedInstructionCount) / float64(metrics.OriginalInstructionCount) * 100
	}

	if metrics.OriginalCyclomaticComplexity > 0 {
		metrics.ComplexityReductionPercent = float64(metrics.OriginalCyclomaticComplexity-metrics.ReducedCyclomaticComplexity) / float64(metrics.OriginalCyclomaticComplexity) * 100
	}

	return metrics
}

// calculateCyclomaticComplexity calculates cyclomatic complexity of the CFG.
func (rg *ReportGenerator) calculateCyclomaticComplexity() int {
	if rg.CFG == nil || len(rg.CFG.Blocks) == 0 {
		return 0
	}

	// Cyclomatic complexity = E - N + 2P
	// E = number of edges, N = number of nodes, P = number of connected components
	// For a single method, P = 1

	edgeCount := 0
	for _, block := range rg.CFG.Blocks {
		edgeCount += len(block.Succs)
	}

	nodeCount := len(rg.CFG.Blocks)
	complexity := edgeCount - nodeCount + 2

	if complexity < 1 {
		complexity = 1
	}

	return complexity
}

// detectObfuscationTechniques detects and reports obfuscation techniques.
func (rg *ReportGenerator) detectObfuscationTechniques() []ObfuscationTechnique {
	techniques := make([]ObfuscationTechnique, 0)

	// Detect opaque predicates
	if rg.OpaquePredicateAnalysis != nil {
		count := len(rg.OpaquePredicateAnalysis.AlwaysTrue) + len(rg.OpaquePredicateAnalysis.AlwaysFalse)
		if count > 0 {
			techniques = append(techniques, ObfuscationTechnique{
				Name:        "Opaque Predicates",
				Description: "Conditional branches with statically known outcomes used to obfuscate control flow",
				Occurrences: count,
				Coverage:    rg.calculateCoverage(count),
				Severity:    "medium",
			})
		}
	}

	// Detect dead code
	if rg.DeadCodeAnalysis != nil {
		count := rg.DeadCodeAnalysis.UnreachableBlockCount() + rg.DeadCodeAnalysis.DeadAssignmentCount()
		if count > 0 {
			techniques = append(techniques, ObfuscationTechnique{
				Name:        "Dead Code",
				Description: "Unreachable code and dead assignments used to increase code size and complexity",
				Occurrences: count,
				Coverage:    rg.calculateCoverage(count),
				Severity:    "low",
			})
		}
	}

	// Detect reflection usage
	if rg.VariableRecovery != nil && rg.VariableRecovery.RecoveryCount() > 0 {
		// Estimate reflection usage based on unrecovered variables
		unrecovered := rg.SSA.VariableCount() - rg.VariableRecovery.RecoveryCount()
		if unrecovered > 0 {
			techniques = append(techniques, ObfuscationTechnique{
				Name:        "Reflection and Dynamic Code",
				Description: "Use of reflection and dynamic code loading to hide method and class references",
				Occurrences: unrecovered,
				Coverage:    rg.calculateCoverage(unrecovered),
				Severity:    "high",
			})
		}
	}

	// Detect pattern-based obfuscation
	if rg.PatternSimplification != nil && len(rg.PatternSimplification.Matches) > 0 {
		techniques = append(techniques, ObfuscationTechnique{
			Name:        "Pattern-Based Obfuscation",
			Description: "Common obfuscation patterns detected and simplified",
			Occurrences: len(rg.PatternSimplification.Matches),
			Coverage:    rg.calculateCoverage(len(rg.PatternSimplification.Matches)),
			Severity:    "medium",
		})
	}

	// Sort by severity
	sort.Slice(techniques, func(i, j int) bool {
		severityOrder := map[string]int{"high": 0, "medium": 1, "low": 2}
		return severityOrder[techniques[i].Severity] < severityOrder[techniques[j].Severity]
	})

	return techniques
}

// calculateCoverage calculates the coverage percentage of a technique.
func (rg *ReportGenerator) calculateCoverage(occurrences int) float64 {
	if rg.CFG == nil || len(rg.CFG.Blocks) == 0 {
		return 0
	}

	totalInstructions := 0
	for _, block := range rg.CFG.Blocks {
		totalInstructions += len(block.Insns)
	}

	if totalInstructions == 0 {
		return 0
	}

	return float64(occurrences) / float64(totalInstructions) * 100
}

// analyzeVariableConfidenceDistribution analyzes the distribution of variable confidence scores.
func (rg *ReportGenerator) analyzeVariableConfidenceDistribution() ConfidenceDistribution {
	dist := ConfidenceDistribution{}

	if rg.VariableRecovery == nil {
		return dist
	}

	for _, result := range rg.VariableRecovery.Results {
		dist.Total++
		switch {
		case result.Confidence >= 80:
			dist.VeryHigh++
		case result.Confidence >= 60:
			dist.High++
		case result.Confidence >= 40:
			dist.Medium++
		case result.Confidence >= 20:
			dist.Low++
		default:
			dist.VeryLow++
		}
	}

	return dist
}

// analyzeMethodConfidenceDistribution analyzes the distribution of method confidence scores.
func (rg *ReportGenerator) analyzeMethodConfidenceDistribution() ConfidenceDistribution {
	dist := ConfidenceDistribution{}

	// This would be populated from method recovery results if available
	// For now, return empty distribution

	return dist
}

// generateRecommendations generates recommendations for further analysis.
func (rg *ReportGenerator) generateRecommendations() []Recommendation {
	recommendations := make([]Recommendation, 0)

	// Recommendation 1: Low variable recovery rate
	if rg.VariableRecovery != nil && rg.SSA != nil {
		recoveryRate := float64(rg.VariableRecovery.RecoveryCount()) / float64(rg.SSA.VariableCount()) * 100
		if recoveryRate < 50 {
			recommendations = append(recommendations, Recommendation{
				Priority:    "high",
				Category:    "variable_recovery",
				Description: fmt.Sprintf("Variable recovery rate is low (%.1f%%). Consider expanding API patterns database or improving usage context analysis.", recoveryRate),
				Action:      "Review unrecovered variables and add new API patterns for common Android APIs.",
			})
		}
	}

	// Recommendation 2: High complexity
	if rg.CFG != nil && rg.calculateCyclomaticComplexity() > 20 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "high",
			Category:    "complexity_reduction",
			Description: fmt.Sprintf("Cyclomatic complexity is high (%d). Consider applying more aggressive simplification passes.", rg.calculateCyclomaticComplexity()),
			Action:      "Enable advanced simplification techniques or apply symbolic execution for better constant propagation.",
		})
	}

	// Recommendation 3: Unresolved reflection
	if rg.VariableRecovery != nil && rg.VariableRecovery.RecoveryCount() < rg.SSA.VariableCount()/2 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "high",
			Category:    "reflection_resolution",
			Description: "Many variables remain unrecovered, suggesting heavy use of reflection or dynamic code.",
			Action:      "Apply reflection resolution pass or enable dynamic code loading analysis.",
		})
	}

	// Recommendation 4: Dead code present
	if rg.DeadCodeAnalysis != nil && rg.DeadCodeAnalysis.UnreachableBlockCount() > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "medium",
			Category:    "dead_code_elimination",
			Description: fmt.Sprintf("Found %d unreachable blocks. Dead code elimination can improve readability.", rg.DeadCodeAnalysis.UnreachableBlockCount()),
			Action:      "Review and remove unreachable code sections.",
		})
	}

	// Recommendation 5: Opaque predicates
	if rg.OpaquePredicateAnalysis != nil && (len(rg.OpaquePredicateAnalysis.AlwaysTrue) > 0 || len(rg.OpaquePredicateAnalysis.AlwaysFalse) > 0) {
		count := len(rg.OpaquePredicateAnalysis.AlwaysTrue) + len(rg.OpaquePredicateAnalysis.AlwaysFalse)
		recommendations = append(recommendations, Recommendation{
			Priority:    "medium",
			Category:    "opaque_predicate_removal",
			Description: fmt.Sprintf("Detected %d opaque predicates. Removing them can significantly simplify control flow.", count),
			Action:      "Apply opaque predicate removal to simplify conditional branches.",
		})
	}

	// Recommendation 6: Manual review
	recommendations = append(recommendations, Recommendation{
		Priority:    "medium",
		Category:    "manual_review",
		Description: "Automated recovery has limitations. Manual review of critical sections is recommended.",
		Action:      "Review recovered names and manually verify correctness of high-value identifiers.",
	})

	return recommendations
}

// generateSummary generates a summary text for the report.
func (rg *ReportGenerator) generateSummary(report *AnalysisReport) string {
	var sb strings.Builder

	sb.WriteString("=== DEOBFUSCATION ANALYSIS SUMMARY ===\n\n")

	// Recovery statistics
	sb.WriteString("RECOVERY STATISTICS:\n")
	sb.WriteString(fmt.Sprintf("  Variables Recovered: %d / %d (%.1f%%)\n",
		report.RecoveryStats.VariablesRecovered,
		report.RecoveryStats.VariablesTotal,
		report.RecoveryStats.VariableRecoveryRate))
	sb.WriteString(fmt.Sprintf("  Constants Recovered: %d / %d (%.1f%%)\n",
		report.RecoveryStats.ConstantsRecovered,
		report.RecoveryStats.ConstantsTotal,
		report.RecoveryStats.ConstantRecoveryRate))

	// Complexity metrics
	sb.WriteString("\nCOMPLEXITY REDUCTION:\n")
	sb.WriteString(fmt.Sprintf("  Cyclomatic Complexity: %d → %d (%.1f%% reduction)\n",
		report.ComplexityMetrics.OriginalCyclomaticComplexity,
		report.ComplexityMetrics.ReducedCyclomaticComplexity,
		report.ComplexityMetrics.ComplexityReductionPercent))
	sb.WriteString(fmt.Sprintf("  Instructions: %d → %d (%.1f%% reduction)\n",
		report.ComplexityMetrics.OriginalInstructionCount,
		report.ComplexityMetrics.ReducedInstructionCount,
		report.ComplexityMetrics.InstructionReductionPercent))

	// Obfuscation techniques
	sb.WriteString("\nDETECTED OBFUSCATION TECHNIQUES:\n")
	for _, technique := range report.ObfuscationTechniques {
		sb.WriteString(fmt.Sprintf("  • %s (%s severity): %d occurrences (%.1f%% coverage)\n",
			technique.Name,
			technique.Severity,
			technique.Occurrences,
			technique.Coverage))
	}

	// Confidence distribution
	sb.WriteString("\nCONFIDENCE DISTRIBUTION (Variables):\n")
	sb.WriteString(fmt.Sprintf("  Very High (80-100): %d\n", report.VariableConfidenceDistribution.VeryHigh))
	sb.WriteString(fmt.Sprintf("  High (60-79):       %d\n", report.VariableConfidenceDistribution.High))
	sb.WriteString(fmt.Sprintf("  Medium (40-59):     %d\n", report.VariableConfidenceDistribution.Medium))
	sb.WriteString(fmt.Sprintf("  Low (20-39):        %d\n", report.VariableConfidenceDistribution.Low))
	sb.WriteString(fmt.Sprintf("  Very Low (0-19):    %d\n", report.VariableConfidenceDistribution.VeryLow))

	return sb.String()
}

// generateDetailedReport generates a detailed report text.
func (rg *ReportGenerator) generateDetailedReport(report *AnalysisReport) string {
	var sb strings.Builder

	sb.WriteString("=== DETAILED ANALYSIS REPORT ===\n\n")

	// Recovery details
	sb.WriteString("RECOVERY ANALYSIS:\n")
	sb.WriteString(fmt.Sprintf("Total variables analyzed: %d\n", report.RecoveryStats.VariablesTotal))
	sb.WriteString(fmt.Sprintf("Variables successfully recovered: %d\n", report.RecoveryStats.VariablesRecovered))
	sb.WriteString(fmt.Sprintf("Recovery rate: %.1f%%\n\n", report.RecoveryStats.VariableRecoveryRate))

	// Complexity analysis
	sb.WriteString("COMPLEXITY ANALYSIS:\n")
	sb.WriteString(fmt.Sprintf("Original cyclomatic complexity: %d\n", report.ComplexityMetrics.OriginalCyclomaticComplexity))
	sb.WriteString(fmt.Sprintf("Reduced cyclomatic complexity: %d\n", report.ComplexityMetrics.ReducedCyclomaticComplexity))
	sb.WriteString(fmt.Sprintf("Complexity reduction: %.1f%%\n\n", report.ComplexityMetrics.ComplexityReductionPercent))

	sb.WriteString(fmt.Sprintf("Original instruction count: %d\n", report.ComplexityMetrics.OriginalInstructionCount))
	sb.WriteString(fmt.Sprintf("Reduced instruction count: %d\n", report.ComplexityMetrics.ReducedInstructionCount))
	sb.WriteString(fmt.Sprintf("Instruction reduction: %.1f%%\n\n", report.ComplexityMetrics.InstructionReductionPercent))

	sb.WriteString(fmt.Sprintf("Unreachable blocks removed: %d\n", report.ComplexityMetrics.UnreachableBlocksRemoved))
	sb.WriteString(fmt.Sprintf("Dead assignments removed: %d\n", report.ComplexityMetrics.DeadAssignmentsRemoved))
	sb.WriteString(fmt.Sprintf("Opaque predicates removed: %d\n", report.ComplexityMetrics.OpaquePredicatesRemoved))
	sb.WriteString(fmt.Sprintf("Loops reconstructed: %d\n", report.ComplexityMetrics.LoopsReconstructed))
	sb.WriteString(fmt.Sprintf("Exception handlers structured: %d\n\n", report.ComplexityMetrics.ExceptionHandlersStructured))

	// Obfuscation techniques
	sb.WriteString("OBFUSCATION TECHNIQUES DETECTED:\n")
	for i, technique := range report.ObfuscationTechniques {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, technique.Name))
		sb.WriteString(fmt.Sprintf("   Description: %s\n", technique.Description))
		sb.WriteString(fmt.Sprintf("   Occurrences: %d\n", technique.Occurrences))
		sb.WriteString(fmt.Sprintf("   Coverage: %.1f%%\n", technique.Coverage))
		sb.WriteString(fmt.Sprintf("   Severity: %s\n\n", technique.Severity))
	}

	// Recommendations
	sb.WriteString("RECOMMENDATIONS:\n")
	for i, rec := range report.Recommendations {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, strings.ToUpper(rec.Priority), rec.Description))
		sb.WriteString(fmt.Sprintf("   Action: %s\n\n", rec.Action))
	}

	return sb.String()
}

// FormatAsText formats the report as plain text.
func (report *AnalysisReport) FormatAsText() string {
	var sb strings.Builder

	sb.WriteString(report.Title)
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("=", len(report.Title)))
	sb.WriteString("\n\n")

	sb.WriteString(report.SummaryText)
	sb.WriteString("\n\n")

	sb.WriteString(report.DetailedText)

	return sb.String()
}

// FormatAsJSON formats the report as JSON (simplified).
func (report *AnalysisReport) FormatAsJSON() string {
	var sb strings.Builder

	sb.WriteString("{\n")
	sb.WriteString(fmt.Sprintf("  \"title\": \"%s\",\n", report.Title))
	sb.WriteString(fmt.Sprintf("  \"timestamp\": \"%s\",\n", report.Timestamp))

	// Recovery stats
	sb.WriteString("  \"recovery_statistics\": {\n")
	sb.WriteString(fmt.Sprintf("    \"variables_recovered\": %d,\n", report.RecoveryStats.VariablesRecovered))
	sb.WriteString(fmt.Sprintf("    \"variables_total\": %d,\n", report.RecoveryStats.VariablesTotal))
	sb.WriteString(fmt.Sprintf("    \"variable_recovery_rate\": %.2f\n", report.RecoveryStats.VariableRecoveryRate))
	sb.WriteString("  },\n")

	// Complexity metrics
	sb.WriteString("  \"complexity_metrics\": {\n")
	sb.WriteString(fmt.Sprintf("    \"original_cyclomatic_complexity\": %d,\n", report.ComplexityMetrics.OriginalCyclomaticComplexity))
	sb.WriteString(fmt.Sprintf("    \"reduced_cyclomatic_complexity\": %d,\n", report.ComplexityMetrics.ReducedCyclomaticComplexity))
	sb.WriteString(fmt.Sprintf("    \"complexity_reduction_percent\": %.2f\n", report.ComplexityMetrics.ComplexityReductionPercent))
	sb.WriteString("  }\n")

	sb.WriteString("}\n")

	return sb.String()
}

// GetSummary returns the summary text.
func (report *AnalysisReport) GetSummary() string {
	return report.SummaryText
}

// GetDetailedReport returns the detailed report text.
func (report *AnalysisReport) GetDetailedReport() string {
	return report.DetailedText
}

// GetRecoveryStatistics returns the recovery statistics.
func (report *AnalysisReport) GetRecoveryStatistics() RecoveryStatistics {
	return report.RecoveryStats
}

// GetComplexityMetrics returns the complexity metrics.
func (report *AnalysisReport) GetComplexityMetrics() ComplexityMetrics {
	return report.ComplexityMetrics
}

// GetObfuscationTechniques returns the detected obfuscation techniques.
func (report *AnalysisReport) GetObfuscationTechniques() []ObfuscationTechnique {
	return report.ObfuscationTechniques
}

// GetRecommendations returns the recommendations.
func (report *AnalysisReport) GetRecommendations() []Recommendation {
	return report.Recommendations
}
