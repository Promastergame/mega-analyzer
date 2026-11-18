package experts

import (
	"encoding/json"
	"testing"

	"decisionai/s1"
)

func TestQuantity(t *testing.T) {
	opts := []s1.Option{{Key: "0", Text: "Хватает полностью"}, {Key: "1", Text: "Не хватает 1-2"}, {Key: "2", Text: "Не хватает 3-5"}, {Key: "3", Text: "Не хватает больше 5"}}
	tf := []s1.Option{{Key: "true", Text: "Денег хватает"}, {Key: "false", Text: "Денег не хватает"}}
	for _, c := range []struct {
		state, instr, typ string
		opts             []s1.Option
		want             float64 // noul: P(true) side (1/0); score: option index; -1 = not handled
	}{
		{`{"деньги_есть":5,"цена_бургера":7}`, "Может ли Петя купить бургер?", s1.TypeNoul, tf, 0},
		{`{"balance":120,"ticket_price":80}`, "Can she afford the ticket?", s1.TypeNoul, nil, 1},
		{`{"balance":120,"ticket_price":80}`, "Is she short of money for the ticket?", s1.TypeNoul, nil, 0},
		{`"У Маши есть 3 литра краски, а для стены нужно 10 литров."`, "Хватит ли краски на стену?", s1.TypeNoul, nil, 0},
		{`{"деньги_есть":5,"цена_бургера":7}`, "Насколько велика нехватка монет?", s1.TypeScore, opts, 1},
		{`{"запас_дисков":2,"нужно_дисков":10}`, "Насколько велика нехватка?", s1.TypeScore, opts, 3},
		{`{"budget":900,"cost":700}`, "How big is the shortfall?", s1.TypeScore, opts, 0},
		{`{"хватает_денег":false,"x":1}`, "Денег хватает?", s1.TypeNoul, nil, 0},
		{`{"user":"bob","age":31}`, "Can he buy alcohol?", s1.TypeNoul, nil, -1},
		{`{"значение":81,"лимит":100}`, "Флогистона слишком много?", s1.TypeNoul, nil, 0},
		{`"Датчик показывает 63 %, лимит 48 %."`, "Нагрузка в норме?", s1.TypeNoul, nil, 0},
		{`{"дней_осталось":20,"дней_нужно":8}`, "Будет опоздание?", s1.TypeNoul, nil, 0},
		{`"Нужно 15 дн., срок через 4 дн."`, "Успеет ли Сабина к сроку?", s1.TypeNoul, nil, 0},
		{`{"список":["a","b","c"]}`, "Больше 2 элементов в списке?", s1.TypeNoul, nil, 1},
		{`{"в_наличии":16,"требуется":30}`, "Будет дефицит?", s1.TypeNoul, nil, 1},
		{`"Вариант «Пиксель»: рейтинг 11. Вариант «Шмель»: рейтинг 54."`, "Пиксель лучше по рейтингу, чем Шмель?", s1.TypeNoul, nil, 0},
		{`{"у_Фили_кракозябр":4,"стоимость_дудки":6}`, "Хватит ли Филе кракозябр на дудку?", s1.TypeNoul, nil, 0},
		{`"У ёжика Тошки в норке 9 орешков. Варенье стоит 2 орешка."`, "Может ли Тошка купить варенье?", s1.TypeNoul, nil, 1},
		{`"На складе 5 рулонов, а для заказа требуется 30 рулонов."`, "Какова нехватка рулонов?", s1.TypeScore, opts, 3},
		{`{"мест_в_лодке":3,"пассажиров":2}`, "Все пассажиры поместятся в лодку?", s1.TypeNoul, nil, 1},
		{`"Пёс выпил 3 миски воды из 3."`, "Пёс выпил всю воду?", s1.TypeNoul, nil, 1},
		{`"Сделано 4 задачи из 10."`, "Сделаны все задачи?", s1.TypeNoul, nil, 0},
		{`{"вес_Гранит":12,"вес_Шмель":85}`, "Какой вариант легче?", s1.TypeChoice, []s1.Option{{Key: "Шмель", Text: "Вариант Шмель"}, {Key: "Гранит", Text: "Вариант Гранит"}}, 1},
	} {
		var st any
		json.Unmarshal([]byte(c.state), &st)
		stText := c.state
		if s, ok := st.(string); ok {
			stText = s
		}
		a, ok := Quantity{}.Answer(st, stText, s1.ExpertQuestion{Type: c.typ, Instr: c.instr, Options: c.opts})
		got := -1.0
		if ok {
			if c.typ == s1.TypeNoul {
				got = 0
				if a.Probs[0] > 0.5 {
					got = 1
				}
			} else {
				got = float64(argmaxF(a.Probs))
			}
		}
		if got != c.want {
			t.Errorf("%s / %s: got %v want %v (%v)", c.state, c.instr, got, c.want, a.Evidence)
		}
	}
}

func argmaxF(p []float64) int {
	b := 0
	for i := range p {
		if p[i] > p[b] {
			b = i
		}
	}
	return b
}
