package ml

// ═══════════════════════════════════════════════════════════════════════════════
// DFG INTEGRATION — helper-методы для PatchPoint с DFG
// ═══════════════════════════════════════════════════════════════════════════════
//
// Примечание: сам DFG анализ + scoring теперь в scoredMethodToPoint (patch_predictor.go).
// Этот файл содержит только helper-методы для работы с уже заполненным point.DFG.
// ═══════════════════════════════════════════════════════════════════════════════

// HasDFG проверяет есть ли DFG анализ у PatchPoint
func (p *PatchPoint) HasDFG() bool {
	return p != nil && p.DFG != nil && p.DFG.Available
}

// GetDFGCondition возвращает человекочитаемое условие или ""
func (p *PatchPoint) GetDFGCondition() string {
	if !p.HasDFG() {
		return ""
	}
	return p.DFG.ConditionText
}

// GetDFGTraceSummary возвращает краткое описание trace для отображения
func (p *PatchPoint) GetDFGTraceSummary() []string {
	if !p.HasDFG() {
		return nil
	}

	var summary []string
	for _, step := range p.DFG.Trace {
		switch step.Type {
		case DFGConst:
			summary = append(summary, "const: "+step.ValueString())
		case DFGInvoke:
			summary = append(summary, "invoke: "+step.ValueString())
		case DFGField:
			summary = append(summary, "field: "+step.ValueString())
		case DFGMove:
			summary = append(summary, "move "+step.ValueString())
		}
	}
	return summary
}
