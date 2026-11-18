package s1

import "math"

// CalculationTrace records checked numeric operations, not a generated chain of
// thought. Verified means arithmetic consistency; extraction/source truth still
// needs domain validation. Quantities use one normalized unit throughout.
type CalculationTrace struct {
	Facts            []CalculationFact `json:"facts"`
	InitialAvailable float64           `json:"initial_available"`
	InitialRequired  float64           `json:"initial_required"`
	Steps            []CalculationStep `json:"steps,omitempty"`
	Available        float64           `json:"available"`
	Required         float64           `json:"required"`
	Shortfall        float64           `json:"shortfall"`
	Unit             string            `json:"unit"`
	Enough           bool              `json:"enough"`
	Verified         bool              `json:"verified"`
}
type CalculationFact struct {
	Value  float64 `json:"value"`
	Role   string  `json:"role"`
	Source string  `json:"source"`
}
type CalculationStep struct {
	Target    string  `json:"target"`
	Operation string  `json:"operation"`
	Operand   float64 `json:"operand"`
	Result    float64 `json:"result"`
}

func calculationEqual(a, b float64) bool {
	return !math.IsNaN(a) && !math.IsNaN(b) && !math.IsInf(a, 0) && !math.IsInf(b, 0) && math.Abs(a-b) <= 1e-9*math.Max(1, math.Max(math.Abs(a), math.Abs(b)))
}
func (p CalculationTrace) Verify() bool {
	if p.Unit == "" || !calculationEqual(p.InitialAvailable, p.InitialAvailable) || !calculationEqual(p.InitialRequired, p.InitialRequired) {
		return false
	}
	a, r := p.InitialAvailable, p.InitialRequired
	for _, step := range p.Steps {
		if !calculationEqual(step.Operand, step.Operand) {
			return false
		}
		target := &a
		if step.Target == "required" {
			target = &r
		} else if step.Target != "available" {
			return false
		}
		switch step.Operation {
		case "add":
			*target += step.Operand
		case "subtract":
			*target -= step.Operand
		case "discount_percent":
			if step.Operand < 0 || step.Operand > 100 {
				return false
			}
			*target *= 1 - step.Operand/100
		default:
			return false
		}
		if !calculationEqual(*target, step.Result) {
			return false
		}
	}
	return a >= 0 && r >= 0 && calculationEqual(a, p.Available) && calculationEqual(r, p.Required) && calculationEqual(math.Max(0, r-a), p.Shortfall) && p.Enough == (a > r || calculationEqual(a, r))
}
