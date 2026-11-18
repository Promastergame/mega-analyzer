package experts

import (
	"testing"

	"decisionai/s1"
)

func TestTypedQuantitiesComputeOperations(t *testing.T) {
	for _, tc := range []struct { state, question string; want bool }{
		{"В наличии 2 кг муки. Для рецепта нужно 1500 г муки.", "Хватит ли муки?", true},
		{"В наличии 900 г муки. Для рецепта нужен 1 кг муки.", "Хватит ли муки?", false},
		{"Есть 1.5 л воды. Нужно 1400 мл воды.", "Хватит ли воды?", true},
		{"Есть 750 мл воды. Нужно 0,8 л воды.", "Хватит ли воды?", false},
		{"Бюджет: 1000 рублей. Цена товара: 900 рублей. Обязательная доставка: 200 рублей.", "Хватит ли бюджета на товар с доставкой?", false},
		{"Бюджет: 1000 рублей. Цена товара: 800 рублей. Обязательная доставка: 150 рублей.", "Хватит ли бюджета на товар с доставкой?", true},
		{"Есть 3 коробки по 8 карандашей в каждой. Нужно 20 карандашей.", "Хватит ли карандашей?", true},
		{"Есть 4 коробки по 6 карандашей в каждой. Нужно 25 карандашей.", "Хватит ли карандашей?", false},
		{"В резервуаре было 18 литров воды. Из него слили 5 литров, затем добавили 2 литра. Для полива нужно 16 литров.", "Хватит ли воды?", false},
		{"Есть 850 рублей. Цена куртки до скидки: 1000 рублей. Скидка: 20 процентов. Доставка бесплатная.", "Хватит ли денег на куртку со скидкой?", true},
		{"Есть 750 рублей. Цена товара до скидки: 1000 рублей. Скидка: 20 процентов.", "Хватит ли денег?", false},
		{"В наличии 2 часа. Нужно 120 минут.", "Успеем ли вовремя?", true},
		{"В наличии 2 часа. Нужно 121 минута.", "Успеем ли вовремя?", false},
		{"Available: 3 kg flour. Required: 2800 g flour.", "Is there enough flour?", true},
		{"Budget: 100 dollars. Price: 80 dollars. Shipping: 25 dollars.", "Can I afford it?", false},
		{"У Маши есть 5 рублей. У Пети есть 12 рублей. Цена: 10 рублей.", "Может ли Петя купить товар?", true},
		{"У Маши есть 5 рублей. У Пети есть 12 рублей. Цена: 10 рублей.", "Может ли Маша купить товар?", false},
	} {
		a, ok := (Quantity{}).Answer(tc.state, tc.state, s1.ExpertQuestion{Type: s1.TypeNoul, Instr: tc.question})
		if !ok || a.Abstained || len(a.Probs) != 1 || (a.Probs[0] > .5) != tc.want {
			t.Errorf("%s / %s: handled=%v answer=%+v", tc.state, tc.question, ok, a)
		}
		if ok && len(a.Evidence) == 0 { t.Error("computed answer has no evidence") }
	}
}

func TestTypedQuantitiesBatch2PacksUnitsExtras(t *testing.T) {
	for _, tc := range []struct{ state, question string; want bool }{
		{"Есть 6 запечатанных коробок по 18 карандашей, других карандашей нет. Нужно выдать 126 карандашей.", "Хватит ли карандашей?", false},
		{"Бюджет составляет 1700 рублей. Товар стоит 1580 рублей, обязательная доставка стоит ещё 150 рублей.", "Хватит ли бюджета на товар с доставкой?", false},
		{"В канистре 3,5 л раствора. Для обработки нужно 3600 мл раствора.", "Хватит ли раствора для обработки?", false},
		{"Есть 4 рулона по 2,25 м ленты, другой ленты нет. Нужно получить 9,1 м ленты.", "Хватит ли общей длины ленты?", false},
		{"The supply contains 1.70 kg of resin. The batch requires 1750 g of resin.", "Is there enough resin for the batch?", false},
		{"There are 8 trays with 14 vials each and no other vials. The order requires 112 vials.", "Are there enough vials for the order?", true},
		{"The budget is 95 credits. The item costs 83 credits and mandatory shipping costs an additional 13 credits.", "Does the budget cover the item and shipping?", false},
		{"The tank contains 2.8 L of coolant. The machine requires 2850 mL of coolant.", "Is there enough coolant for the machine?", false},
		{"There are 5 cable reels holding 1.5 m each and no other cable. The job requires a total of 8 m of cable.", "Is the total cable length sufficient for the job?", false},
	} {
		a, ok := (Quantity{}).Answer(tc.state, tc.state, s1.ExpertQuestion{Type: s1.TypeNoul, Instr: tc.question})
		if !ok || a.Abstained || len(a.Probs) != 1 || (a.Probs[0] > .5) != tc.want {
			t.Errorf("%s / %s: handled=%v answer=%+v", tc.state, tc.question, ok, a)
		}
	}
}

func TestTypedQuantitiesCoverageScore(t *testing.T) {
	opts := []s1.Option{
		{Key: "0", Text: "Запас меньше 25% потребности"},
		{Key: "1", Text: "Запас от 25% включительно до 50% не включительно"},
		{Key: "2", Text: "Запас от 50% включительно до 100% не включительно"},
		{Key: "3", Text: "Запас не меньше 100% потребности"},
	}
	for _, tc := range []struct {
		state string
		want  string
	}{
		{"В запасе 240 г порошка. Для партии требуется 1 кг порошка.", "0"},
		{"В запасе 250 г порошка. Для партии требуется 1 кг порошка.", "1"},
		{"В резервуаре 500 мл жидкости. Для запуска требуется 1 л жидкости.", "2"},
		{"В запасе 990 г гранул. Для заказа требуется 1 кг гранул.", "2"},
	} {
		a, ok := (Quantity{}).Answer(tc.state, tc.state, s1.ExpertQuestion{Type: s1.TypeScore, Instr: "Какой уровень покрытия потребности соответствует запасу?", Options: opts})
		if !ok || a.Abstained {
			t.Errorf("%s: handled=%v answer=%+v", tc.state, ok, a)
			continue
		}
		best := -1
		for i, p := range a.Probs {
			if best < 0 || p > a.Probs[best] {
				best = i
			}
		}
		if best < 0 || opts[best].Key != tc.want {
			t.Errorf("%s: got %+v want %s (%+v)", tc.state, a.Probs, tc.want, a)
		}
	}
}

func TestTypedQuantitiesDoNotGuessIncompatibleFacts(t *testing.T) {	for _, state := range []string{
		"Есть 2 кг сахара. Нужно 1 кг муки.",
		"Есть 100 долларов. Нужно 80 евро.",
		"Есть 3 литра краски. Нужно 2 кг краски.",
		"Есть 50 рублей. Есть 200 рублей. Цена: 100 рублей.",
		"Есть примерно 1 кг муки. Нужно 900 г муки.",
		"Бюджет 100 рублей. Цена: 80 рублей. Необязательная доставка: 50 рублей.",
	} {
		a, ok := (Quantity{}).Answer(state, state, s1.ExpertQuestion{Type: s1.TypeNoul, Instr: "Хватит ли запаса?"})
		if !ok || !a.Abstained || a.Calibrated { t.Errorf("guessed for %q: %+v, %v", state, a, ok) }
	}
}
