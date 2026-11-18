package experts

// Temporary diagnostic: traces Quantity expert on failing quantity items.
import (
	"fmt"
	"testing"

	"decisionai/s1"
)

func TestDebugQuantity(t *testing.T) {
	cases := []struct{ name, state, instr string }{
		{"q004", "Есть 6 запечатанных коробок по 18 карандашей, других карандашей нет. Нужно выдать 126 карандашей.", "Хватит ли карандашей?"},
		{"q005", "Бюджет составляет 1700 рублей. Товар стоит 1580 рублей, обязательная доставка стоит ещё 150 рублей.", "Хватит ли бюджета на товар с доставкой?"},
		{"q008", "В канистре 3,5 л раствора. Для обработки нужно 3600 мл раствора.", "Хватит ли раствора для обработки?"},
		{"q014", "There are 8 trays with 14 vials each and no other vials. The order requires 112 vials.", "Are there enough vials for the order?"},
	}
	for _, c := range cases {
		facts, complex := quantityFacts(c.state)
		fmt.Printf("=== %s complex=%v\n", c.name, complex)
		for _, f := range facts {
			fmt.Printf("  fact value=%g unit=%q dim=%q role=%q obj=%q owner=%q ev=%q\n",
				f.value, f.unit, f.dimension, f.role, f.object, f.owner, f.evidence)
		}
		q := s1.ExpertQuestion{ID: "q", Type: s1.TypeNoul, Instr: c.instr}
		a, ok := Quantity{}.Answer(nil, c.state, q)
		fmt.Printf("  handled=%v probs=%v\n", ok, a.Probs)
	}
}
