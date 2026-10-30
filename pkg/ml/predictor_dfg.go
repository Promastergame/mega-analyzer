package ml

import (
	"mega-analyzer/pkg/internal/cfg"
)


// ═══════════════════════════════════════════════════════════════════════════════
// DFG TYPES — Data Flow Graph analysis for PatchPoint
// ═══════════════════════════════════════════════════════════════════════════════

// convertCFGTraceToML конвертирует CFG TraceStep в ML DFGTraceStep.
//
// 💥 PHASE 1 FIX: раньше функция читала из `step.Value`, который cfg.DFGAnalyzer
// никогда не заполняет — Trace() пишет только Instruction/Register/Notes
// (см. pkg/internal/cfg/dfg.go::traceRegInBlock). Это приводило к тому что
// все шаги становились DFGUnknown, и per-step бонусы (DFGInvoke/DFGConst/
// DFGField) в patch_predictor никогда не срабатывали — DFG бонус сводился
// только к базовой контрибуции license check.
//
// Сейчас извлекаем тип из step.Instruction, где cfg.DFGAnalyzer.Analyze()
// корректно заполняет ConstVal/InvokeRef/FieldRef/MoveSrc.
func convertCFGTraceToML(steps []cfg.TraceStep) []DFGTraceStep {
	result := make([]DFGTraceStep, 0, len(steps))

	for _, step := range steps {
		dfgStep := DFGTraceStep{
			Register: step.Register,
			// Confidence по умолчанию 0.8 для backward DFG (DFG cfg-уровня
			// не вычисляет per-step confidence; это делается на уровне ml).
			Confidence: 0.8,
		}

		instr := step.Instruction
		if instr == nil {
			dfgStep.Type = DFGUnknown
			result = append(result, dfgStep)
			continue
		}

		// Приоритет: const → invoke → field → move.
		// Source-of-truth — поля Instruction, заполняемые DFGAnalyzer.Analyze().
		switch {
		case instr.ConstVal != nil:
			dfgStep.Type = DFGConst
			dfgStep.ConstValue = instr.ConstVal
		case instr.InvokeRef != "":
			dfgStep.Type = DFGInvoke
			ref := instr.InvokeRef
			dfgStep.InvokeRef = &ref
		case instr.FieldRef != "":
			dfgStep.Type = DFGField
			ref := instr.FieldRef
			dfgStep.FieldRef = &ref
		case instr.MoveSrc != "":
			dfgStep.Type = DFGMove
			ms := instr.MoveSrc
			dfgStep.MoveFrom = &ms
		default:
			dfgStep.Type = DFGUnknown
		}

		result = append(result, dfgStep)
	}

	return result
}

// DFGValueType тип значения в trace (strong typing)
type DFGValueType string

const (
	DFGConst   DFGValueType = "const"   // const-string, const/4
	DFGInvoke  DFGValueType = "invoke"  // invoke-* → move-result
	DFGField   DFGValueType = "field"   // iget/sget
	DFGMove    DFGValueType = "move"    // move from another register
	DFGUnknown DFGValueType = "unknown" // не определено
)

// DFGTraceStep один шаг в цепочке data flow
type DFGTraceStep struct {
	Type     DFGValueType // const / invoke / field / move
	Register string       // какой регистр (v0, v1)

	// Только одно из этих полей заполнено (в зависимости от Type)
	ConstValue *string // для DFGConst
	InvokeRef  *string // для DFGInvoke (LClass;->method()Z)
	FieldRef   *string // для DFGField (LClass;->field:I)
	MoveFrom   *string // для DFGMove (исходный регистр)

	Confidence float64 // уверенность 0-1
}

// IsValid проверяет инвариант: заполнено только одно поле значения
func (s DFGTraceStep) IsValid() bool {
	count := 0
	if s.ConstValue != nil {
		count++
	}
	if s.InvokeRef != nil {
		count++
	}
	if s.FieldRef != nil {
		count++
	}
	if s.MoveFrom != nil {
		count++
	}
	// Должно быть ровно 0 или 1 (0 для unknown допустимо)
	return count <= 1
}

// ValueString возвращает строковое представление значения (для отладки)
func (s DFGTraceStep) ValueString() string {
	switch s.Type {
	case DFGConst:
		if s.ConstValue != nil {
			return *s.ConstValue
		}
	case DFGInvoke:
		if s.InvokeRef != nil {
			return *s.InvokeRef
		}
	case DFGField:
		if s.FieldRef != nil {
			return *s.FieldRef
		}
	case DFGMove:
		if s.MoveFrom != nil {
			return "from " + *s.MoveFrom
		}
	}
	return "?"
}

// DFGInfo структурированный DFG анализ для PatchPoint
type DFGInfo struct {
	Available     bool           `json:"available"`      // true если DFG есть
	ConditionType string         `json:"condition_type"` // if-eqz, if-nez, etc
	ConditionText string         `json:"condition_text"` // человекочитаемо: "v0 == false"
	Register      string         `json:"register"`       // регистр в условии
	Trace         []DFGTraceStep `json:"trace"`          // полная цепочка
	Confidence    float64        `json:"confidence"`     // общая уверенность
}

// Validate проверяет что все шаги trace валидны
func (d DFGInfo) Validate() bool {
	for _, step := range d.Trace {
		if !step.IsValid() {
			return false
		}
	}
	return true
}
