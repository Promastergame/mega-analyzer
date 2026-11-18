package semai

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"strings"

	"decisionai/gnn"
)

// Synthetic stories for training/evaluating the event GNN. Labels come from the generator
// (who moved what where), not from rules applied to the text.

type place struct{ nom, gen, acc, prep, in, out string } // in: "в"/"на", out: "из"/"с"
type thing struct {
	acc1, gen2, gen5 string
	fem              bool
	neut             bool
	anim             bool // can move by itself: "3 ученика ушли"
}
type person struct {
	nom, gen string
	fem      bool
	dat      string
}
type verb struct{ m, f string }

var synPlaces = []place{
	{"коробка", "коробки", "коробку", "коробке", "в", "из"}, {"корзина", "корзины", "корзину", "корзине", "в", "из"},
	{"ваза", "вазы", "вазу", "вазе", "в", "из"}, {"банка", "банки", "банку", "банке", "в", "из"},
	{"сумка", "сумки", "сумку", "сумке", "в", "из"}, {"мешок", "мешка", "мешок", "мешке", "в", "из"},
	{"ящик", "ящика", "ящик", "ящике", "в", "из"}, {"шкаф", "шкафа", "шкаф", "шкафу", "в", "из"},
	{"холодильник", "холодильника", "холодильник", "холодильнике", "в", "из"}, {"копилка", "копилки", "копилку", "копилке", "в", "из"},
	{"кошелек", "кошелька", "кошелек", "кошельке", "в", "из"}, {"пакет", "пакета", "пакет", "пакете", "в", "из"},
	{"рюкзак", "рюкзака", "рюкзак", "рюкзаке", "в", "из"}, {"тарелка", "тарелки", "тарелку", "тарелке", "на", "с"},
	{"полка", "полки", "полку", "полке", "на", "с"}, {"стол", "стола", "стол", "столе", "на", "со"},
	{"шкатулка", "шкатулки", "шкатулку", "шкатулке", "в", "из"}, {"кастрюля", "кастрюли", "кастрюлю", "кастрюле", "в", "из"},
	{"аквариум", "аквариума", "аквариум", "аквариуме", "в", "из"}, {"гараж", "гаража", "гараж", "гараже", "в", "из"},
	{"склад", "склада", "склад", "складе", "на", "со"}, {"тумбочка", "тумбочки", "тумбочку", "тумбочке", "в", "из"},
	{"класс", "класса", "класс", "классе", "в", "из"}, {"автобус", "автобуса", "автобус", "автобусе", "в", "из"},
	{"комната", "комнаты", "комнату", "комнате", "в", "из"}, {"зал", "зала", "зал", "зале", "в", "из"},
	{"поляна", "поляны", "поляну", "поляне", "на", "с"},
}

var synThings = []thing{
	{"конфету", "конфеты", "конфет", true, false, false}, {"яблоко", "яблока", "яблок", false, true, false}, {"монету", "монеты", "монет", true, false, false},
	{"карандаш", "карандаша", "карандашей", false, false, false}, {"печеньку", "печеньки", "печенек", true, false, false}, {"орех", "ореха", "орехов", false, false, false},
	{"мяч", "мяча", "мячей", false, false, false}, {"книгу", "книги", "книг", true, false, false}, {"игрушку", "игрушки", "игрушек", true, false, false},
	{"ложку", "ложки", "ложек", true, false, false}, {"грушу", "груши", "груш", true, false, false}, {"мандарин", "мандарина", "мандаринов", false, false, false},
	{"шарик", "шарика", "шариков", false, false, false}, {"кубик", "кубика", "кубиков", false, false, false}, {"пирожок", "пирожка", "пирожков", false, false, false},
	{"огурец", "огурца", "огурцов", false, false, false}, {"яйцо", "яйца", "яиц", false, true, false}, {"рыбку", "рыбки", "рыбок", true, false, false},
	{"банан", "банана", "бананов", false, false, false}, {"тетрадь", "тетради", "тетрадей", true, false, false}, {"гвоздь", "гвоздя", "гвоздей", false, false, false},
	{"сливу", "сливы", "слив", true, false, false}, {"марку", "марки", "марок", true, false, false}, {"ракушку", "ракушки", "ракушек", true, false, false},
	{"рубль", "рубля", "рублей", false, false, false}, {"наклейку", "наклейки", "наклеек", true, false, false}, {"пуговицу", "пуговицы", "пуговиц", true, false, false},
	{"розу", "розы", "роз", true, false, false}, {"кружку", "кружки", "кружек", true, false, false}, {"бутылку", "бутылки", "бутылок", true, false, false},
	{"ученик", "ученика", "учеников", false, false, true}, {"пассажир", "пассажира", "пассажиров", false, false, true},
	{"гость", "гостя", "гостей", false, false, true}, {"птицу", "птицы", "птиц", true, false, true}, {"котенок", "котенка", "котят", false, false, true},
	{"утку", "утки", "уток", true, false, true}, {"ребенок", "ребенка", "детей", false, false, true}, {"туриста", "туриста", "туристов", false, false, true},
}

var animThings = func() []thing {
	var out []thing
	for _, t := range synThings {
		if t.anim {
			out = append(out, t)
		}
	}
	return out
}()

var synPeople = []person{
	{"мальчик", "мальчика", false, "мальчику"}, {"девочка", "девочки", true, "девочке"}, {"маша", "маши", true, "маше"}, {"петя", "пети", false, "пете"},
	{"мама", "мамы", true, "маме"}, {"папа", "папы", false, "папе"}, {"бабушка", "бабушки", true, "бабушке"}, {"дедушка", "дедушки", false, "дедушке"},
	{"вася", "васи", false, "васе"}, {"катя", "кати", true, "кате"}, {"саша", "саши", false, "саше"}, {"оля", "оли", true, "оле"},
	{"брат", "брата", false, "брату"}, {"сестра", "сестры", true, "сестре"}, {"дима", "димы", false, "диме"}, {"лена", "лены", true, "лене"},
	{"друг", "друга", false, "другу"}, {"подруга", "подруги", true, "подруге"}, {"коля", "коли", false, "коле"}, {"аня", "ани", true, "ане"},
}

func vb(ms ...string) []verb {
	var out []verb
	for _, m := range ms {
		if i := strings.Index(m, "|"); i > 0 {
			out = append(out, verb{m[:i], m[i+1:]})
		} else {
			out = append(out, verb{m, m + "а"})
		}
	}
	return out
}

var (
	takeVerbs = vb("взял", "достал", "вынул", "вытащил", "забрал", "унес|унесла", "стащил", "утащил", "выложил", "убрал", "вытряхнул",
		"выудил", "отсыпал", "изъял", "выгреб|выгребла", "выгрузил", "похитил", "украл", "вычерпал", "вынес|вынесла", "отобрал", "извлек|извлекла", "выковырял", "схватил")
	eatVerbs = vb("съел", "слопал", "скушал", "сгрыз|сгрызла", "проглотил")
	putVerbs = vb("убрал", "положил", "вернул", "добавил", "подложил", "доложил", "насыпал", "засунул", "спрятал", "сложил", "кинул", "бросил",
		"подбросил", "опустил", "вложил", "впихнул", "загрузил", "ссыпал", "поместил", "докинул", "закинул", "запихнул", "поставил", "подсыпал", "закатил")
	gainVerbs = vb("купил", "нашел|нашла", "получил", "выиграл", "заработал", "собрал", "раздобыл", "нарвал", "поймал", "приобрел|приобрела", "добыл", "накопил")
	loseVerbs = vb("потерял", "отдал", "продал", "подарил", "выбросил", "раздал", "обронил", "уронил", "одолжил", "пожертвовал", "выкинул", "посеял",
		"потратил", "заплатил", "истратил", "проиграл", "разбил", "сломал", "раздарил")
	nopVerbs = vb("посчитал", "пересчитал", "увидел", "понюхал", "сфотографировал", "нарисовал", "показал", "потрогал", "заметил", "осмотрел", "сосчитал", "назвал",
		"посмотрел на|посмотрела на", "описал", "запомнил", "проверил", "разглядел", "полюбил")
	moveVerbs = vb("переложил", "пересыпал", "перенес|перенесла", "переставил", "перекинул")
	giveVerbs = vb("дал", "вернул", "подарил", "принес|принесла", "отдал", "передал", "одолжил", "прислал")
	// impersonal plural ("утром привезли 40 ящиков") and self-moving items ("3 ученика ушли")
	inPlural   = []string{"привезли", "принесли", "доставили", "завезли", "подвезли", "положили", "добавили", "подкинули", "занесли", "подсыпали", "подложили", "загрузили"}
	outPlural  = []string{"увезли", "унесли", "вывезли", "забрали", "вынесли", "взяли", "вытащили", "съели", "выгрузили", "растащили", "раскупили", "выбросили"}
	comeVerbs  = []string{"пришли", "зашли", "вошли", "приехали", "прибежали", "прилетели", "приплыли", "вернулись", "заселились", "сели"}
	leaveVerbs = []string{"ушли", "вышли", "уехали", "убежали", "улетели", "уплыли", "сбежали", "выбежали", "вылетели", "разошлись"}
	spoilVerbs = []string{"завяли", "испортились", "сломались", "потрескались", "засохли", "помялись", "сгнили", "запылились"}
	dropPlural = []string{"выбросили", "выкинули", "убрали", "унесли", "съели", "вынесли"}
	timeAdv    = []string{"утром ", "вечером ", "днем ", "через час ", "на следующий день ", "в обед "}
)

func filtS(xs []string, heldOut bool) []string {
	var out []string
	for _, x := range xs {
		if HeldOutVerb(x) == heldOut {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return xs
	}
	return out
}

// HeldOutVerb reports whether a verb is reserved for the unseen-verb test split (~25%).
func HeldOutVerb(v string) bool {
	h := fnv.New32a()
	h.Write([]byte(v))
	return h.Sum32()%4 == 0
}

type synClause struct {
	text  string
	label string // "" when the clause has no number
}

// EventExample is one generated story.
type EventExample struct {
	State, Question string
	Labels          []string
	Answer          string // yes | no | number
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.Intn(len(xs))] }

func numWord(r *rand.Rand, n int, t thing) string {
	if r.Intn(4) == 0 {
		switch n {
		case 1:
			if t.fem {
				return "одну " + t.acc1
			} else if t.neut {
				return "одно " + t.acc1
			}
			return "один " + t.acc1
		case 2:
			if t.fem {
				return "две " + t.gen2
			}
			return "два " + t.gen2
		case 3:
			return "три " + t.gen2
		case 5:
			return "пять " + t.gen5
		}
	}
	return fmt.Sprintf("%d %s", n, countForm(n, t))
}

func countForm(n int, t thing) string {
	switch {
	case n%100 >= 11 && n%100 <= 14:
		return t.gen5
	case n%10 == 1:
		return t.acc1
	case n%10 >= 2 && n%10 <= 4:
		return t.gen2
	}
	return t.gen5
}

// GenerateEvents makes n stories. heldOut selects verbs: false = training verbs only, true = held-out only.
func GenerateEvents(n int, seed int64, heldOut bool) []EventExample {
	r := rand.New(rand.NewSource(seed))
	filt := func(vs []verb) []verb {
		var out []verb
		for _, v := range vs {
			if HeldOutVerb(v.m) == heldOut {
				out = append(out, v)
			}
		}
		if len(out) == 0 {
			return vs
		}
		return out
	}
	take, eat, put, gain, lose, nop, move, give := filt(takeVerbs), filt(eatVerbs), filt(putVerbs), filt(gainVerbs), filt(loseVerbs), filt(nopVerbs), filt(moveVerbs), filt(giveVerbs)
	inPl, outPl, come, leave, spoil, dropPl := filtS(inPlural, heldOut), filtS(outPlural, heldOut), filtS(comeVerbs, heldOut), filtS(leaveVerbs, heldOut), filtS(spoilVerbs, heldOut), filtS(dropPlural, heldOut)
	var out []EventExample
	for len(out) < n {
		P := pick(r, synPlaces)
		P2 := pick(r, synPlaces)
		for P2.nom == P.nom {
			P2 = pick(r, synPlaces)
		}
		T := pick(r, synThings)
		if r.Intn(6) == 0 {
			T = pick(r, animThings)
		}
		T2 := pick(r, synThings)
		for T2.gen5 == T.gen5 {
			T2 = pick(r, synThings)
		}
		A := pick(r, synPeople)
		B := pick(r, synPeople)
		for B.nom == A.nom {
			B = pick(r, synPeople)
		}
		agentTarget := r.Intn(3) == 0
		vf := func(v verb) string {
			if A.fem {
				return v.f
			}
			return v.m
		}
		var cl []synClause
		delta, init, hasInit := 0, 0, false
		// effect relative to the target
		eff := func(onPlace, onAgent int) string {
			e := onPlace
			if agentTarget {
				e = onAgent
			}
			return map[int]string{1: "plus", -1: "minus", 0: "none"}[e]
		}
		apply := func(lab string, k int) {
			if lab == "plus" {
				delta += k
			} else if lab == "minus" {
				delta -= k
			}
		}
		otherPlace := false
		if r.Intn(2) == 0 {
			k := 3 + r.Intn(15)
			if r.Intn(4) == 0 {
				k = 10 + r.Intn(190)
			}
			verbless := r.Intn(6) == 0
			if agentTarget {
				cl = append(cl, synClause{fmt.Sprintf("%s %s было %d %s", pick(r, []string{"у", "сначала у"}), A.gen, k, countForm(k, T)), "init"})
			} else if verbless {
				cl = append(cl, synClause{fmt.Sprintf("%s %s %d %s", P.in, P.prep, k, countForm(k, T)), "init"})
			} else {
				cl = append(cl, synClause{fmt.Sprintf("%s%s %s %s %d %s", pick(r, []string{"", "сначала "}), P.in, P.prep, pick(r, []string{"было", "лежало", "находилось", "было", "стояло", "хранилось"}), k, countForm(k, T)), "init"})
			}
			init, hasInit = k, true
			// a fact about another place/person is not the start value
			if r.Intn(3) == 0 {
				k2 := 2 + r.Intn(9)
				if r.Intn(2) == 0 {
					cl = append(cl, synClause{fmt.Sprintf("%s %s было %d %s", P2.in, P2.prep, k2, countForm(k2, T)), "none"})
				} else {
					cl = append(cl, synClause{fmt.Sprintf("%s %s %s %d %s", pick(r, []string{"а", "и"}), P2.in, P2.prep, k2, countForm(k2, T)), "none"})
				}
				otherPlace = true
			}
		}
		mentioned := hasInit && !agentTarget
		held := 0 // items the agent took out of the target place and still holds
		steps := 1 + r.Intn(4)
		first := true
		lastLab := ""
		for s := 0; s < steps; s++ {
			k := 1 + r.Intn(9)
			subj := ""
			if first {
				subj = pick(r, []string{A.nom + " ", A.nom + " ", ""})
				first = false
			} else if r.Intn(4) == 0 {
				subj = pick(r, []string{"он ", "она ", A.nom + " "})
				if A.fem && subj == "он " {
					subj = "она "
				} else if !A.fem && subj == "она " {
					subj = "он "
				}
			}
			// eating / losing / spending without a place: from the hands if the agent holds some,
			// otherwise from the only place the story is about.
			implied := func() string {
				if agentTarget {
					return "minus"
				}
				if held == 0 && mentioned && !otherPlace {
					return "minus"
				}
				return "none"
			}
			var txt, lab string
			extra := "" // second clause carried by a pronoun ("и положил их в холодильник")
			extraLab := ""
			switch c := r.Intn(19); {
			case c < 3: // take from target place
				v := pick(r, take)
				if mentioned && r.Intn(3) == 0 { // place implied by the story: "потом взял ещё 5"
					txt = fmt.Sprintf("%s%s %s", subj, vf(v), bareNum(r, k, T))
				} else if mentioned && r.Intn(4) == 0 {
					txt = fmt.Sprintf("%s%s %s %s %d", subj, vf(v), P.out, P.gen, k)
				} else if r.Intn(2) == 0 {
					txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(v), P.out, P.gen, numWord(r, k, T))
				} else {
					txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(v), numWord(r, k, T), P.out, P.gen)
				}
				lab = eff(-1, 1)
				held += k
				if r.Intn(4) == 0 { // "взяла 2 яблока из вазы и съела их": already out of the place
					extra = fmt.Sprintf("%s %s", vf(pick(r, eat)), "их")
					extraLab = eff(0, -1)
					held = max(0, held-k)
				}
			case c < 6: // put into target place
				v := pick(r, put)
				switch r.Intn(5) {
				case 3:
					if mentioned {
						txt = fmt.Sprintf("%s%s %s", subj, vf(v), bareNum(r, k, T))
					} else {
						txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(v), P.in, P.acc, numWord(r, k, T))
					}
				case 4:
					txt = fmt.Sprintf("%s%s %s %s %d", subj, vf(v), P.in, P.acc, k)
				case 0:
					txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(v), P.in, P.acc, numWord(r, k, T))
				case 1:
					txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(v), numWord(r, k, T), P.in, P.acc)
				default:
					if mentioned {
						txt = fmt.Sprintf("%s%s %s %s", subj, vf(v), bareNum(r, k, T), pick(r, []string{"обратно", "назад", "на место"}))
					} else {
						txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(v), P.in, P.acc, numWord(r, k, T))
					}
				}
				lab = eff(1, -1)
				held = max(0, held-k)
			case c == 6: // eat
				v := pick(r, eat)
				if r.Intn(2) == 0 {
					txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(v), numWord(r, k, T), P.out, P.gen)
					lab = eff(-1, 0)
				} else {
					txt = fmt.Sprintf("%s%s %s", subj, vf(v), numWord(r, k, T))
					lab = implied()
					held = max(0, held-k)
				}
			case c == 7: // agent gains / loses outside the place
				if r.Intn(2) == 0 {
					txt = fmt.Sprintf("%s%s %s", subj, vf(pick(r, gain)), numWord(r, k, T))
					lab = eff(0, 1)
					if r.Intn(2) == 0 { // "купил 6 яиц и положил их в холодильник"
						extra = fmt.Sprintf("%s %s %s %s", vf(pick(r, put)), pick(r, []string{"их", "их", "его", "все их"}), P.in, P.acc)
						extraLab = eff(1, -1)
					}
				} else {
					txt = fmt.Sprintf("%s%s %s", subj, vf(pick(r, lose)), numWord(r, k, T))
					lab = implied()
					held = max(0, held-k)
				}
			case c == 8: // other place or other item: does not touch the target
				if o := r.Intn(4); o == 0 {
					txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(pick(r, take)), P2.out, P2.gen, numWord(r, k, T))
					lab = eff(0, 1)
					otherPlace = true
				} else if o == 1 { // "взяла 2 яблока из вазы"
					txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(pick(r, take)), numWord(r, k, T), P2.out, P2.gen)
					lab = eff(0, 1)
					otherPlace = true
					if r.Intn(2) == 0 { // "… и съела их": the other place's apples, not the target's
						extra = fmt.Sprintf("%s %s", vf(pick(r, eat)), "их")
						extraLab = eff(0, -1)
					}
				} else if o == 2 { // "положила 4 яблока в вазу" (another place)
					if r.Intn(2) == 0 {
						txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(pick(r, put)), numWord(r, k, T), P2.in, P2.acc)
					} else {
						txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(pick(r, put)), P2.in, P2.acc, numWord(r, k, T))
					}
					lab = eff(0, -1)
					otherPlace = true
				} else {
					txt = fmt.Sprintf("%s%s %s %s %s", subj, vf(pick(r, put)), P.in, P.acc, numWord(r, k, T2))
					lab = "none"
				}
			case c == 9: // move between places
				v := pick(r, move)
				if r.Intn(2) == 0 {
					txt = fmt.Sprintf("%s%s %s %s %s %s %s", subj, vf(v), numWord(r, k, T), P.out, P.gen, P2.in, P2.acc)
					lab = eff(-1, 0)
				} else {
					txt = fmt.Sprintf("%s%s %s %s %s %s %s", subj, vf(v), numWord(r, k, T), P2.out, P2.gen, P.in, P.acc)
					lab = eff(1, 0)
				}
				otherPlace = true
			case c == 10: // looked / counted: no change
				v := vf(pick(r, nop))
				if r.Intn(2) == 0 {
					txt = fmt.Sprintf("%s%s %s %s %s", subj, v, numWord(r, k, T), P.in, P.prep)
				} else {
					txt = fmt.Sprintf("%s%s %s", subj, v, numWord(r, k, T))
				}
				lab = "none"
			case c == 11: // transfers between people
				if r.Intn(2) == 0 {
					txt = fmt.Sprintf("%s%s %s %s", subj, vf(pick(r, []verb{{"отдал", "отдала"}, {"подарил", "подарила"}, {"одолжил", "одолжила"}, {"передал", "передала"}, {"дал", "дала"}})), B.dat, numWord(r, k, T))
					lab = eff(0, -1)
				} else {
					v := pick(r, give)
					vb := v.m
					if B.fem {
						vb = v.f
					}
					to := pick(r, []string{A.dat, "ему", "ей"})
					if to == "ему" && A.fem {
						to = "ей"
					} else if to == "ей" && !A.fem {
						to = "ему"
					}
					txt = fmt.Sprintf("%s %s %s %s", B.nom, vb, to, numWord(r, k, T))
					lab = eff(0, 1)
				}
			case c == 12 || c == 13: // impersonal plural: "утром привезли 40 ящиков на склад"
				if agentTarget {
					s--
					continue
				}
				k = 1 + r.Intn(60)
				if hasInit {
					k = 1 + r.Intn(max(3, init/2+1))
				}
				adv := ""
				if r.Intn(2) == 0 {
					adv = pick(r, timeAdv)
				}
				if r.Intn(2) == 0 {
					where := ""
					if !mentioned || r.Intn(2) == 0 {
						where = " " + P.in + " " + P.acc
					}
					txt = fmt.Sprintf("%s%s %d %s%s", adv, pick(r, inPl), k, countForm(k, T), where)
					lab = "plus"
				} else {
					where := ""
					if !mentioned || r.Intn(2) == 0 {
						where = " " + P.out + " " + P.gen
					} else if r.Intn(2) == 0 { // "2 стула унесли на кухню": out of the story's place, into another
						where = " " + P2.in + " " + P2.acc
					}
					if r.Intn(3) == 0 {
						txt = fmt.Sprintf("%s%d %s %s%s", adv, k, countForm(k, T), pick(r, outPl), where)
					} else {
						txt = fmt.Sprintf("%s%s %d %s%s", adv, pick(r, outPl), k, countForm(k, T), where)
					}
					lab = "minus"
				}
			case c == 14: // self-moving items: "3 ученика ушли домой", "зашли 8 пассажиров"
				if !T.anim || agentTarget {
					s--
					continue
				}
				k = 2 + r.Intn(12)
				adv := ""
				if r.Intn(2) == 0 {
					adv = pick(r, []string{"на остановке ", "потом ", "после урока ", "через час ", "вечером "})
				}
				var v, where string
				if r.Intn(2) == 0 {
					v, lab = pick(r, come), "plus"
					if !mentioned || r.Intn(3) == 0 {
						where = " " + P.in + " " + P.acc
					}
				} else {
					v, lab = pick(r, leave), "minus"
					if !mentioned || r.Intn(3) == 0 {
						where = " " + pick(r, []string{P.out + " " + P.gen, "домой", "гулять", P.out + " " + P.gen})
					}
				}
				if r.Intn(2) == 0 {
					txt = fmt.Sprintf("%s%d %s %s%s", adv, k, countForm(k, T), v, where)
				} else {
					txt = fmt.Sprintf("%s%s %d %s%s", adv, v, k, countForm(k, T), where)
				}
			case c == 15: // "2 розы завяли и их выбросили"
				if agentTarget || !mentioned {
					s--
					continue
				}
				txt = fmt.Sprintf("%s %s", numWord(r, k, T), pick(r, spoil))
				lab = "none"
				if r.Intn(3) > 0 {
					extra = fmt.Sprintf("%s %s", pick(r, []string{"их", "их"}), pick(r, dropPl))
					extraLab = "minus"
				}
			default: // ellipsis: "потом ещё 2" repeats the previous action
				if lastLab == "" {
					s--
					continue
				}
				txt = fmt.Sprintf("ещё %s", bareNum(r, k, T))
				lab = lastLab
			}
			if lab != "init" {
				lastLab = lab
			}
			if strings.Contains(txt, " "+P.gen) || strings.Contains(txt, " "+P.acc) || strings.Contains(txt, " "+P.prep) {
				mentioned = true
			}
			if strings.Contains(txt, " ещё ") || r.Intn(6) == 0 && !strings.HasPrefix(txt, "ещё") {
				// "взял ещё 5"
				txt = strings.Replace(txt, fmt.Sprint(k)+" ", "ещё "+fmt.Sprint(k)+" ", 1)
			}
			if r.Intn(10) == 0 { // "через 10 минут Маша положила…"
				if r.Intn(3) == 0 {
					txt = fmt.Sprintf("%s %s", pick(r, []string{"через час", "через минуту", "через день", "спустя час"}), txt)
				} else {
					txt = fmt.Sprintf("%s %d %s %s", pick(r, []string{"через", "спустя"}), 2+r.Intn(40), pick(r, []string{"минут", "минут", "секунд", "часа"}), txt)
				}
			}
			apply(lab, k)
			cl = append(cl, synClause{strings.TrimSpace(txt), lab})
			if extra != "" {
				cl = append(cl, synClause{"и " + extra, extraLab})
				apply(extraLab, k)
				lastLab = extraLab
				if strings.Contains(extra, " "+P.acc) {
					mentioned = true
				}
			}
		}
		if r.Intn(5) == 0 { // time distractor
			at := r.Intn(len(cl) + 1)
			nc := append([]synClause{}, cl[:at]...)
			nc = append(nc, synClause{fmt.Sprintf("%s %d %s", pick(r, []string{"прошло", "прошло", "подождали"}), 2+r.Intn(30), pick(r, []string{"минут", "минуты", "часов", "дня"})), ""})
			cl = append(nc, cl[at:]...)
		}
		var b strings.Builder
		var labels []string
		for i, c := range cl {
			if i > 0 {
				if strings.HasPrefix(c.text, "и ") && c.label != "none" {
					b.WriteString(" ")
				} else if strings.HasPrefix(c.text, "а ") || strings.HasPrefix(c.text, "и ") {
					b.WriteString(", ")
				} else {
					b.WriteString(pick(r, []string{", потом ", ", затем ", ". Потом ", ", а потом ", ". Затем ", ", после этого ", ", и потом ", ". ", ", "}))
				}
			}
			b.WriteString(c.text)
			if c.label != "" {
				labels = append(labels, c.label)
			}
		}
		rs := []rune(b.String())
		state := strings.ToUpper(string(rs[:1])) + string(rs[1:])
		// question about the target
		var q, ans string
		where := P.in + " " + P.prep
		if agentTarget {
			where = "у " + A.gen
		}
		item := T.gen5
		if r.Intn(10) == 0 {
			if T.gen5 == "монет" || T.gen5 == "рублей" {
				item = "денег"
			} else {
				item = pick(r, []string{"предметов", "штук", "вещей"})
			}
		}
		switch r.Intn(8) {
		case 0:
			q = fmt.Sprintf("Стало ли %s %s меньше, чем было %s?", item, where, pick(r, []string{"вначале", "сначала", "изначально"}))
			ans = ynStr(delta < 0)
		case 1:
			q = pick(r, []string{fmt.Sprintf("Стало ли %s %s меньше?", item, where), fmt.Sprintf("Стало ли %s меньше %s?", where, item), fmt.Sprintf("%s стало меньше %s?", cap1(where), item)})
			ans = ynStr(delta < 0)
		case 2:
			q = pick(r, []string{fmt.Sprintf("Стало ли %s %s больше, чем было вначале?", item, where), fmt.Sprintf("Стало ли %s %s больше?", item, where), fmt.Sprintf("Стало ли %s больше %s?", where, item)})
			ans = ynStr(delta > 0)
		case 3:
			q = fmt.Sprintf("Изменилось ли количество %s %s?", item, where)
			ans = ynStr(delta != 0)
		case 4:
			q = pick(r, []string{fmt.Sprintf("Осталось ли %s %s столько же, сколько было?", item, where), fmt.Sprintf("Осталось ли %s %s столько же?", item, where)})
			ans = ynStr(delta == 0)
		default:
			q = pick(r, []string{fmt.Sprintf("Сколько %s стало %s?", item, where), fmt.Sprintf("Сколько %s осталось %s?", item, where),
				fmt.Sprintf("Сколько %s %s?", item, where), fmt.Sprintf("Сколько теперь %s %s?", item, where), fmt.Sprintf("Сколько %s сейчас %s?", item, where)})
			if hasInit {
				ans = fmt.Sprint(init + delta)
			} else {
				ans = "unknown"
			}
		}
		// keep only stories whose clause split matches the generator
		cs := splitEvents(state)
		nn := 0
		for _, c := range cs {
			if c.HasNum {
				nn++
			}
		}
		if nn != len(labels) {
			continue
		}
		out = append(out, EventExample{State: state, Question: q, Labels: labels, Answer: ans})
	}
	return out
}

func ynStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// EventGraphs converts examples to labelled GNN graphs.
func EventGraphs(ex []EventExample) []*gnn.Graph {
	idx := map[string]int{}
	for i, c := range EventClasses {
		idx[c] = i
	}
	var out []*gnn.Graph
	for _, e := range ex {
		cs := splitEvents(e.State)
		g := EventGraph(cs, eventTarget(e.Question, cs))
		for _, l := range e.Labels {
			g.Labels = append(g.Labels, idx[l])
		}
		out = append(out, g)
	}
	return out
}

// bareNum sometimes drops the noun ("вернул 2 обратно", "взял ещё 5").
func bareNum(r *rand.Rand, n int, t thing) string {
	if r.Intn(2) == 0 {
		return fmt.Sprint(n)
	}
	return numWord(r, n, t)
}

func cap1(s string) string {
	rs := []rune(s)
	return strings.ToUpper(string(rs[:1])) + string(rs[1:])
}
