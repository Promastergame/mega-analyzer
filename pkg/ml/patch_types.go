package ml

// ═══════════════════════════════════════════════════════════════════════════════
// GENERATED PATCH
// ═══════════════════════════════════════════════════════════════════════════════

// GeneratedPatch — готовый патч для метода
type GeneratedPatch struct {
	// ── Оригинал ─────────────────────────────────────────────────
	OriginalCode  string `json:"original_code"`
	OriginalLines int    `json:"original_lines"`

	// ── Патч ─────────────────────────────────────────────────────
	PatchedCode  string `json:"patched_code"`
	PatchedLines int    `json:"patched_lines"`

	// ── Diff ─────────────────────────────────────────────────────
	DiffView string `json:"diff_view"`

	// ── Метаданные ───────────────────────────────────────────────
	PatchType       PatchType `json:"patch_type"`
	Description     string    `json:"description"`
	Hint            string    `json:"hint"`
	MethodName      string    `json:"method_name"`
	MethodSignature string    `json:"method_signature,omitempty"`
	FilePath        string    `json:"file_path"`

	// ── Для Markdown ─────────────────────────────────────────────
	OriginalBlock string `json:"-"`
	PatchedBlock  string `json:"-"`

	// ── Enhanced fields for ML Patcher Improvements ──────────────
	Mode                PatchMode            `json:"mode"`
	Explanation         PatchExplanation     `json:"explanation"`
	Confidence          float64              `json:"confidence"`
	ConfidenceBreakdown *ConfidenceBreakdown `json:"confidence_breakdown,omitempty"`
	Artifact            *PatchArtifact       `json:"artifact,omitempty"`

	// Runtime decision (auto_patch | needs_review | reject) из финальной
	// калибровки PatchPoint.
	RuntimeConfidence *RuntimeConfidence `json:"runtime_confidence,omitempty"`
	RuntimeDecision   string             `json:"runtime_decision,omitempty"`

	// Structured per-instruction accounting (P1#2/P2#6): which canonical
	// body lines a surgical strategy changed or deliberately left alone,
	// instead of parsing it back out of Description text.
	ModifiedLines []int `json:"modified_lines,omitempty"`
	SkippedLines  []int `json:"skipped_lines,omitempty"`
	// TargetInstruction is the data-selected canonical body line the edit
	// addresses, or NoTargetInstruction (-1) for whole-method heuristics.
	TargetInstruction int `json:"target_instruction"`
	// StrategyID identifies the concrete strategy that produced the patch
	// (StrategyMetadata.ID), linking detection → strategy → outcome.
	StrategyID string `json:"strategy_id,omitempty"`
	// ReturnCoverage replaces prose-based completeness checks for built-in injectors.
	ReturnCoverage *ReturnSiteCoverage `json:"return_coverage,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE BREAKDOWN
// ═══════════════════════════════════════════════════════════════════════════════

// ConfidenceBreakdown shows detailed signal contributions to confidence score
type ConfidenceBreakdown struct {
	BaseConfidence      float64              `json:"base_confidence"`
	SignalContributions []SignalContribution `json:"signal_contributions"`
	MultiSignalBonus    float64              `json:"multi_signal_bonus"`
	ObfuscationAdjust   float64              `json:"obfuscation_adjust"`
	FinalConfidence     float64              `json:"final_confidence"`
}

// SignalContribution represents a single signal's contribution to confidence
type SignalContribution struct {
	SignalType   string  `json:"signal_type"`
	Value        string  `json:"value"`
	Weight       float64 `json:"weight"`
	Confidence   float64 `json:"confidence"`
	Contribution float64 `json:"contribution"` // weight * confidence
}
