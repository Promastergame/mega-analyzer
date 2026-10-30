package ml

import (
	"sort"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH PLANNER — единый путь кандидаты → генерация → проверки → выбор (P2#6).
//
// Раньше было три разных пути: SelectStrategyWithSignals + Generate,
// tryRankedFallback и GenerateBest. Отказ на поздней стадии (контракт,
// структурный префлайт) не обязательно приводил к следующему кандидату, а
// причины отсева нигде не сохранялись. Планировщик делает один проход:
// ранжирует по запросу, генерирует каждого кандидата, проверяет контракт
// запроса и структуру, выбирает первый чистый. Все кандидаты, причины отсева
// и запасные варианты сохраняются в PlannedPatch.
// ═══════════════════════════════════════════════════════════════════════════════

// Drop reasons — machine-readable, для отчётов и будущего обучения ранжира.
const (
	DropInvalidRequest   = "invalid_request"
	DropNotApplicable    = "not_applicable"
	DropNoChange         = "no_change"
	DropGenerateError    = "generate_error"
	DropEmptyPatch       = "empty_patch"
	DropContractMismatch = "contract_mismatch"
	DropStructInvalid    = "struct_invalid"
	DropPartialDeferred  = "partial_deferred"
	DropSuperseded       = "superseded_by_clean"
)

// CandidateOutcome — судьба одного кандидата.
type CandidateOutcome struct {
	Strategy   PatchStrategy
	StrategyID string
	Assessment StrategyAssessment
	Score      float64
	Patch      *GeneratedPatch
	// DropReason пуст только у выбранного кандидата.
	DropReason string
	// Partial — кандидат валиден структурно, но это частичный форс.
	Partial bool
	// Error and Validation keep diagnostics even for rejected candidates.
	Error      string
	Validation *ValidationResult
}

// PlannedPatch — итог планирования.
type PlannedPatch struct {
	Request    *ChangeRequest
	Candidates []CandidateOutcome
	// Patch — выбранный чистый патч либо лучший частичный (IsPartial).
	Patch      *GeneratedPatch
	Strategy   PatchStrategy
	StrategyID string
	IsPartial  bool
	Validation *ValidationResult
	// RejectionReason is machine-readable; Error explains invalid requests.
	RejectionReason string
	Error           string
}

// rankWithRequest ранжирует стратегии по запросу: оценка применимости со
// свидетельствами плюс буст совпавшему желаемому исходу. Детерминирован.
func (ss *StrategySelector) rankWithRequest(req *ChangeRequest) []CandidateOutcome {
	candidates := ss.assessCandidates(req)
	out := make([]CandidateOutcome, 0, len(candidates))
	for _, c := range candidates {
		if c.Assessment.Applicable {
			out = append(out, c)
		}
	}
	return out
}

func (ss *StrategySelector) assessCandidates(req *ChangeRequest) []CandidateOutcome {
	if ss == nil || validateChangeRequest(req) != nil {
		return nil
	}
	out := []CandidateOutcome{}
	for _, strategy := range ss.strategies {
		if strategy == nil {
			continue
		}
		assessment := assessStrategyWithRequest(strategy, req)
		dropReason := ""
		if !assessment.Applicable {
			dropReason = DropNotApplicable
		}
		score := assessment.Score
		if assessment.Applicable && req.Desired != "" && strategySupportsDesired(strategy, string(req.Desired)) {
			score += 100
		}
		out = append(out, CandidateOutcome{
			Strategy:   strategy,
			StrategyID: strategyIDOf(strategy),
			Assessment: assessment,
			Score:      score,
			DropReason: dropReason,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Assessment.Applicable != out[j].Assessment.Applicable {
			return out[i].Assessment.Applicable
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func strategyIDOf(strategy PatchStrategy) string {
	if d, ok := strategy.(StrategyDescriber); ok {
		if id := d.Metadata().ID; id != "" {
			return id
		}
	}
	return "unknown_strategy"
}

// RankStrategiesWithRequest — публичная ранжировка по запросу.
func (ss *StrategySelector) RankStrategiesWithRequest(req *ChangeRequest) []RankedStrategy {
	ranked := ss.rankWithRequest(req)
	out := make([]RankedStrategy, 0, len(ranked))
	for _, c := range ranked {
		out = append(out, RankedStrategy{
			Strategy:   c.Strategy,
			Assessment: c.Assessment,
			Score:      c.Score,
		})
	}
	return out
}

// PlanPatch прогоняет кандидатов по рангу: генерация → контракт запроса →
// структурная валидация → выбор. Первый чистый побеждает; иначе лучший
// частичный; причины отсева сохраняются у каждого кандидата.
func (ss *StrategySelector) PlanPatch(req *ChangeRequest) *PlannedPatch {
	planned := &PlannedPatch{Request: req}
	if err := validateChangeRequest(req); err != nil {
		planned.RejectionReason = DropInvalidRequest
		planned.Error = err.Error()
		return planned
	}
	if !hasConcreteMethodBody(req.Method.RawBody) {
		planned.RejectionReason = "no_concrete_method_body"
		planned.Error = "no executable Smali body; signature-only synthesis is not a planned edit"
		return planned
	}
	if ss == nil {
		planned.RejectionReason = "missing_selector"
		return planned
	}
	planned.Candidates = ss.assessCandidates(req)
	if len(planned.Candidates) == 0 {
		planned.RejectionReason = "no_candidates"
		return planned
	}
	validator := NewSmaliValidator()
	bestPartial := -1
	original := canonicalPatchText(strings.Join(req.Method.RawBody, "\n"))
	for i := range planned.Candidates {
		c := &planned.Candidates[i]
		if !c.Assessment.Applicable {
			continue
		}
		patch, err := generateWithRequest(c.Strategy, req)
		if err != nil || patch == nil {
			c.DropReason = DropGenerateError
			if err != nil {
				c.Error = err.Error()
			} else {
				c.Error = "strategy returned a nil patch"
			}
			continue
		}
		if strings.TrimSpace(patch.PatchedCode) == "" {
			c.DropReason = DropEmptyPatch
			continue
		}
		normalizePatchTarget(patch)
		if err := VerifyPatchAgainstRequest(req, patch); err != nil {
			c.DropReason = DropContractMismatch
			c.Error = err.Error()
			continue
		}
		if original != "" && canonicalPatchText(patch.PatchedCode) == original {
			c.DropReason = DropNoChange
			continue
		}
		validation := validator.ValidateStrict(patch.PatchedCode)
		// Run the same body-structure checks used by buildArtifact before
		// accepting a winner, so a late rejection cannot suppress alternatives.
		if validation.Valid && requiresStructurePreservation(patch.PatchType) && original != "" {
			validation.merge(preflightBodyStructure(original, canonicalPatchText(patch.PatchedCode)))
		}
		c.Validation = &validation
		if !validation.Valid {
			c.DropReason = DropStructInvalid
			continue
		}
		c.Patch = patch
		patch.MethodName = req.Method.Name
		patch.MethodSignature = req.Method.FullSignature
		patch.FilePath = req.Method.FilePath
		patch.StrategyID = c.StrategyID
		if isPartialForcedPatch(patch) {
			c.Partial = true
			c.DropReason = DropPartialDeferred
			if bestPartial < 0 {
				bestPartial = i
			}
			continue
		}
		planned.Patch = patch
		planned.Validation = c.Validation
		planned.Strategy = c.Strategy
		planned.StrategyID = c.StrategyID
		for j := range planned.Candidates {
			if j != i && planned.Candidates[j].Patch == nil && planned.Candidates[j].DropReason == "" {
				planned.Candidates[j].DropReason = DropSuperseded
			}
		}
		return planned
	}
	if bestPartial >= 0 {
		c := &planned.Candidates[bestPartial]
		planned.Patch = c.Patch
		planned.Validation = c.Validation
		planned.Strategy = c.Strategy
		planned.StrategyID = c.StrategyID
		planned.IsPartial = true
		c.DropReason = ""
	} else {
		planned.RejectionReason = "no_valid_candidate"
	}
	return planned
}

// normalizePatchTarget приводит TargetInstruction к документированному виду:
// стратегии, не выбравшие инструкцию, оставляют ноль — это то же "нет цели",
// что и NoTargetInstruction.
func normalizePatchTarget(patch *GeneratedPatch) {
	if patch == nil {
		return
	}
	if patch.TargetInstruction == 0 && len(patch.ModifiedLines) == 0 {
		patch.TargetInstruction = NoTargetInstruction
	}
}

// GenerateBest пробует стратегии по рангу до первой валидной — теперь поверх
// единого планировщика, чтобы контракт запроса и структурные проверки
// действовали и здесь.
func (ss *StrategySelector) GenerateBest(
	mi *shared.MethodInfo,
	mode PatchMode,
	signals []VulnSignal,
) (*GeneratedPatch, PatchStrategy, error) {
	req, err := BuildChangeRequest(mi, mode, signals)
	if err != nil {
		return nil, nil, err
	}
	planned := ss.PlanPatch(req)
	if planned == nil || planned.Patch == nil {
		return nil, nil, nil
	}
	return planned.Patch, planned.Strategy, nil
}
