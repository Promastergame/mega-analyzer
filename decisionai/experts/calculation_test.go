package experts

import (
	"decisionai/s1"
	"testing"
)

func TestTypedQuantityReturnsCheckedCalculation(t *testing.T) {
	q := s1.ExpertQuestion{Type: s1.TypeNoul, Instr: "Хватит ли денег?"}
	a, ok := typedQuantityAnswer("Бюджет 1000 рублей. Стоимость товара 900 рублей. Обязательная доставка 200 рублей.", q)
	if !ok || a.Calculation == nil || !a.Calculation.Verify() || a.Calculation.Enough || a.Calculation.Shortfall != 100 {
		t.Fatalf("missing or incorrect calculation: %+v", a)
	}
}
