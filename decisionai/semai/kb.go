package semai

import "strings"

// Regions of the body axis (head → tail). A part count is a [head, front, rear, tail] vector.
type partCount struct {
	N        [4]int
	Regional bool
}

func (p partCount) Total() int { return p.N[0] + p.N[1] + p.N[2] + p.N[3] }

// regionSpan: where each region lies on the 0..1 head→tail axis.
var regionSpan = [4][2]float64{{0, 0.15}, {0.15, 0.5}, {0.5, 0.9}, {0.9, 1}}

type word struct {
	RU  []string // prefixes
	EN  []string // exact forms
	Not []string // ru prefixes that must not match
}

func (w word) match(tok string) bool {
	for _, e := range w.EN {
		if tok == e {
			return true
		}
	}
	for _, p := range w.RU {
		if strings.HasPrefix(tok, p) {
			for _, n := range w.Not {
				if strings.HasPrefix(tok, n) {
					return false
				}
			}
			return true
		}
	}
	return false
}

type partKind struct {
	ID      string
	Title   string // ru title (genitive plural)
	Matcher word
}

var partKinds = []partKind{
	{"ear", "ушей", word{RU: []string{"уш", "ух"}, EN: []string{"ear", "ears"}, Not: []string{"ушк", "ушел", "ушл", "ушиб", "ушат", "ушан", "ухаж", "ухудш", "ухожен"}}},
	{"eye", "глаз", word{RU: []string{"глаз", "глаж"}, EN: []string{"eye", "eyes"}}},
	{"leg", "ног", word{RU: []string{"ног", "ноже", "ножк", "лап"}, EN: []string{"leg", "legs", "paw", "paws", "foot", "feet"}, Not: []string{"ногот", "ногт", "ногам"[:0] + "нога_"}}},
	{"arm", "рук", word{RU: []string{"рук", "руч"}, EN: []string{"arm", "arms", "hand", "hands"}, Not: []string{"рукав"}}},
	{"tail", "хвостов", word{RU: []string{"хвост"}, EN: []string{"tail", "tails"}}},
	{"head", "голов", word{RU: []string{"голов"}, EN: []string{"head", "heads"}}},
	{"horn", "рогов", word{RU: []string{"рог"}, EN: []string{"horn", "horns"}, Not: []string{"рогат"}}},
	{"wing", "крыльев", word{RU: []string{"крыл"}, EN: []string{"wing", "wings"}}},
	{"finger", "пальцев", word{RU: []string{"пальц", "палец"}, EN: []string{"finger", "fingers"}}},
	{"tusk", "бивней", word{RU: []string{"бивн"}, EN: []string{"tusk", "tusks"}}},
	{"nose", "носов", word{RU: []string{"нос"}, EN: []string{"nose", "noses"}, Not: []string{"носк", "носил", "носит"}}},
	{"tentacle", "щупалец", word{RU: []string{"щупалец", "щупальц"}, EN: []string{"tentacle", "tentacles"}}},
	{"wheel", "колёс", word{RU: []string{"колес", "колёс"}, EN: []string{"wheel", "wheels"}}},
	{"door", "дверей", word{RU: []string{"двер"}, EN: []string{"door", "doors"}}},
	{"side", "сторон", word{RU: []string{"сторон"}, EN: []string{"side", "sides"}}},
	{"corner", "углов", word{RU: []string{"угл", "угол", "вершин"}, EN: []string{"corner", "corners", "vertex", "vertices"}}},
	{"face", "граней", word{RU: []string{"гран"}, EN: []string{"face", "faces"}}},
	{"edge", "рёбер", word{RU: []string{"ребр", "рёбр", "ребер"}, EN: []string{"edge", "edges"}}},
}

type entity struct {
	ID    string
	Title string // ru nominative singular
	Match word
	Parts map[string]partCount
}

func m4(h, f, r, t int) partCount { return partCount{N: [4]int{h, f, r, t}, Regional: true} }
func flat(n int) partCount        { return partCount{N: [4]int{n, 0, 0, 0}} }

func quadruped(extra map[string]partCount) map[string]partCount {
	p := map[string]partCount{"ear": m4(2, 0, 0, 0), "eye": m4(2, 0, 0, 0), "leg": m4(0, 2, 2, 0), "tail": m4(0, 0, 0, 1), "head": m4(1, 0, 0, 0), "nose": m4(1, 0, 0, 0)}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

var entities = []entity{
	{"mouse", "мышь", word{RU: []string{"мыш"}, EN: []string{"mouse", "mice"}, Not: []string{"мышц", "мышл", "мышк"}}, quadruped(nil)},
	{"rat", "крыса", word{RU: []string{"крыс"}, EN: []string{"rat", "rats"}}, quadruped(nil)},
	{"cat", "кошка", word{RU: []string{"кош", "кот"}, EN: []string{"cat", "cats", "kitten", "kittens"}, Not: []string{"котл", "котор", "коте", "котел", "кошел", "кошма", "кошар"}}, quadruped(nil)},
	{"dog", "собака", word{RU: []string{"собак", "пёс", "пес", "псов", "щен"}, EN: []string{"dog", "dogs", "puppy", "puppies"}, Not: []string{"песн", "песо", "песк"}}, quadruped(nil)},
	{"rabbit", "кролик", word{RU: []string{"кролик", "кролич", "зайц", "заяц", "зайч"}, EN: []string{"rabbit", "rabbits", "hare", "hares", "bunny"}}, quadruped(nil)},
	{"horse", "лошадь", word{RU: []string{"лошад", "конь", "коня", "коней", "коне"}, EN: []string{"horse", "horses"}}, quadruped(map[string]partCount{"hoof": m4(0, 2, 2, 0)})},
	{"cow", "корова", word{RU: []string{"коров", "бык", "быч"}, EN: []string{"cow", "cows", "bull", "bulls"}}, quadruped(map[string]partCount{"horn": m4(2, 0, 0, 0)})},
	{"pig", "свинья", word{RU: []string{"свин", "поросен", "поросён"}, EN: []string{"pig", "pigs"}}, quadruped(nil)},
	{"sheep", "овца", word{RU: []string{"овц", "ове", "баран"}, EN: []string{"sheep", "lamb", "lambs"}}, quadruped(nil)},
	{"bear", "медведь", word{RU: []string{"медвед"}, EN: []string{"bear", "bears"}}, quadruped(nil)},
	{"wolf", "волк", word{RU: []string{"волк", "волч"}, EN: []string{"wolf", "wolves"}}, quadruped(nil)},
	{"fox", "лиса", word{RU: []string{"лис"}, EN: []string{"fox", "foxes"}, Not: []string{"лист", "лиск"}}, quadruped(nil)},
	{"elephant", "слон", word{RU: []string{"слон"}, EN: []string{"elephant", "elephants"}}, quadruped(map[string]partCount{"tusk": m4(2, 0, 0, 0)})},
	{"deer", "олень", word{RU: []string{"олен", "олень"}, EN: []string{"deer"}}, quadruped(map[string]partCount{"horn": m4(2, 0, 0, 0)})},
	{"human", "человек", word{RU: []string{"человек", "люди", "людей", "людям", "людь", "челове"}, EN: []string{"human", "humans", "person", "people", "man", "men", "woman", "women", "child", "children"}}, map[string]partCount{
		"ear": m4(2, 0, 0, 0), "eye": m4(2, 0, 0, 0), "head": m4(1, 0, 0, 0), "nose": m4(1, 0, 0, 0), "arm": m4(0, 2, 0, 0), "finger": m4(0, 10, 0, 0), "leg": m4(0, 0, 2, 0), "tail": m4(0, 0, 0, 0), "horn": m4(0, 0, 0, 0), "wing": m4(0, 0, 0, 0)}},
	{"monkey", "обезьяна", word{RU: []string{"обезьян"}, EN: []string{"monkey", "monkeys"}}, quadruped(map[string]partCount{"arm": m4(0, 2, 0, 0)})},
	{"bird", "птица", word{RU: []string{"птиц", "птенц", "курица", "кур", "утк", "утён", "гус", "голуб", "воробь", "воробе"}, EN: []string{"bird", "birds", "chicken", "chickens", "duck", "ducks", "goose", "pigeon"}, Not: []string{"курс", "курт", "курь"}}, map[string]partCount{
		"eye": m4(2, 0, 0, 0), "head": m4(1, 0, 0, 0), "leg": m4(0, 0, 2, 0), "wing": m4(0, 2, 0, 0), "tail": m4(0, 0, 0, 1)}},
	{"spider", "паук", word{RU: []string{"паук", "паўк"}, EN: []string{"spider", "spiders"}}, map[string]partCount{"leg": m4(0, 4, 4, 0), "eye": m4(8, 0, 0, 0), "head": m4(1, 0, 0, 0)}},
	{"insect", "насекомое", word{RU: []string{"насеком", "муха", "мух", "комар", "пчел", "пчёл", "жук", "жуч"}, EN: []string{"insect", "insects", "fly", "flies", "bee", "bees", "beetle"}, Not: []string{"мухомор"}}, map[string]partCount{"leg": m4(0, 2, 4, 0), "wing": m4(0, 2, 2, 0), "head": m4(1, 0, 0, 0)}},
	{"octopus", "осьминог", word{RU: []string{"осьминог"}, EN: []string{"octopus", "octopuses", "octopi"}}, map[string]partCount{"tentacle": m4(0, 8, 0, 0), "leg": m4(0, 8, 0, 0), "arm": m4(0, 8, 0, 0), "eye": m4(2, 0, 0, 0), "head": m4(1, 0, 0, 0)}},
	{"snake", "змея", word{RU: []string{"змей", "змеи", "змея", "зме"}, EN: []string{"snake", "snakes"}}, map[string]partCount{"eye": m4(2, 0, 0, 0), "head": m4(1, 0, 0, 0), "tail": m4(0, 0, 0, 1), "leg": m4(0, 0, 0, 0)}},
	{"table", "стол", word{RU: []string{"стол", "столов", "столы"}, EN: []string{"table", "tables"}, Not: []string{"столи", "столб", "столк", "столь", "столп"}}, map[string]partCount{"leg": {N: [4]int{4, 0, 0, 0}}}},
	{"chair", "стул", word{RU: []string{"стул", "кресл"}, EN: []string{"chair", "chairs"}}, map[string]partCount{"leg": {N: [4]int{4, 0, 0, 0}}}},
	{"car", "машина", word{RU: []string{"машин", "автомоб", "авто"}, EN: []string{"car", "cars"}}, map[string]partCount{"wheel": m4(0, 2, 2, 0), "door": m4(0, 2, 2, 0)}},
	{"bicycle", "велосипед", word{RU: []string{"велосипед"}, EN: []string{"bicycle", "bicycles", "bike", "bikes"}}, map[string]partCount{"wheel": m4(0, 1, 1, 0)}},
	{"triangle", "треугольник", word{RU: []string{"треугольн"}, EN: []string{"triangle", "triangles"}}, map[string]partCount{"side": flat(3), "corner": flat(3)}},
	{"square", "квадрат", word{RU: []string{"квадрат"}, EN: []string{"square", "squares"}}, map[string]partCount{"side": flat(4), "corner": flat(4)}},
	{"cube", "куб", word{RU: []string{"куб"}, EN: []string{"cube", "cubes"}, Not: []string{"кубок", "кубк"}}, map[string]partCount{"face": flat(6), "edge": flat(12), "corner": flat(8)}},
}

func findPart(tok string) *partKind {
	for i := range partKinds {
		if partKinds[i].Matcher.match(tok) {
			return &partKinds[i]
		}
	}
	return nil
}
func findEntity(tok string) *entity {
	for i := range entities {
		if entities[i].Match.match(tok) {
			return &entities[i]
		}
	}
	return nil
}
