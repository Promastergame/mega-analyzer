package semai

import (
	"fmt"
	"strings"
)

// Facts solver: small deterministic world model for "has N, costs M, can X buy Y?" questions.
// It never guesses: every yes/no comes with the arithmetic that produced it, and anything it
// cannot bind (unknown price, different currency, ambiguous owner) is reported as unknown.

// FactAnswer is the result of SolveFacts.
type FactAnswer struct {
	Answer     string        `json:"answer"` // yes | no | unknown
	Who        []string      `json:"who,omitempty"`
	Confidence float64       `json:"confidence"`
	Reasoning  []string      `json:"reasoning"`
	Solver     string        `json:"solver"`
	Steps      []EventClause `json:"steps,omitempty"` // events solver: what every step did
	Total      *EventTotal   `json:"total,omitempty"`
}

// EventTotal is the most likely outcome of an events story.
type EventTotal struct {
	Delta     float64  `json:"delta"`
	Start     *float64 `json:"start,omitempty"`
	End       *float64 `json:"end,omitempty"`
	Target    string   `json:"target,omitempty"`
	Item      string   `json:"item,omitempty"`
	ScenarioP float64  `json:"scenario_p"`
	// Others: the same story counted for the other places/people it mentions ("а в вазе: 5 → 3").
	Others []EventTotal `json:"others,omitempty"`
}

type qty struct {
	val  float64
	unit string // key of the unit word ("" = none)
	word string
}

type world struct {
	have     map[string][]qty // owner key -> amounts
	owners   []string         // display names in order of appearance
	ownerTxt map[string]string
	price    map[string]qty // item key -> unit price
	priceTxt map[string]string
	stock    map[string]float64 // item key -> available count
	stockTxt map[string]string
	discount *float64 // active discount, percent
	discOff  bool
	notes    []string
}

func key(w string) string {
	r := []rune(stem(w))
	if len(r) > 4 {
		r = r[:4]
	}
	return string(r)
}

var (
	priceVerbs = map[string]bool{"стоит": true, "стоят": true, "стоил": true, "стоила": true, "стоило": true, "costs": true, "cost": true}
	priceNouns = map[string]bool{"цена": true, "цене": true, "стоимость": true, "price": true}
	haveVerbs  = map[string]bool{"есть": true, "имеет": true, "имеется": true, "накопил": true, "накопила": true, "лежит": true, "лежат": true, "has": true, "have": true}
	buyVerbs   = map[string]bool{"купить": true, "приобрести": true, "оплатить": true, "buy": true, "afford": true}
	fillers    = map[string]bool{"всего": true, "только": true, "лишь": true, "ровно": true, "уже": true, "целых": true, "аж": true, "около": true}
	placeWords = map[string]bool{"магазин": true, "магазине": true, "лавке": true, "наличии": true, "складе": true, "продаже": true, "store": true, "shop": true}
	pronouns   = map[string]bool{"он": true, "она": true, "они": true, "him": true, "he": true, "she": true}
)

func isNumber(t string) (float64, bool) {
	if n, ok := parseNumTok(t, 0); ok {
		return n.Val, true
	}
	if n, ok := parseWordNum([]string{t}, 0); ok {
		return n.Val, true
	}
	return 0, false
}

func factClauses(s string) [][]string {
	var out [][]string
	for _, c := range clauseSplit.Split(normText(s), -1) {
		var ts []string
		for _, t := range tokens(c) {
			if t == "," || t == "-" || t == ":" || t == "—" {
				continue
			}
			ts = append(ts, t)
		}
		if len(ts) > 0 {
			out = append(out, ts)
		}
	}
	return out
}

// nextWord returns the first word after i skipping fillers.
func nextWord(ts []string, i int) (string, int) {
	for j := i; j < len(ts); j++ {
		if isWord(ts[j]) && !fillers[ts[j]] {
			return ts[j], j
		}
	}
	return "", -1
}

func (w *world) addOwner(name string) string {
	k := key(name)
	if _, ok := w.ownerTxt[k]; !ok {
		w.ownerTxt[k] = name
		w.owners = append(w.owners, k)
	}
	return k
}

func (w *world) read(ts []string) {
	joined := " " + strings.Join(ts, " ") + " "
	// discount
	if strings.Contains(joined, " скидк") {
		neg := strings.Contains(joined, " не ") || strings.Contains(joined, " нет ")
		if neg {
			w.discOff = true
			w.notes = append(w.notes, "скидка не действует — цена без изменений")
		} else {
			for i, t := range ts {
				if v, ok := isNumber(t); ok && i+1 < len(ts) && (ts[i+1] == "%" || strings.HasPrefix(ts[i+1], "процент")) {
					p := v
					w.discount = &p
				}
			}
			if w.discount == nil {
				w.notes = append(w.notes, "упомянута скидка без размера — её не учитываю")
			}
		}
		return
	}
	for i, t := range ts {
		v, ok := isNumber(t)
		if !ok || (i+1 < len(ts) && ts[i+1] == "%") {
			continue
		}
		unit, _ := nextWord(ts, i+1)
		if _, isN := isNumber(unit); isN || buyVerbs[unit] || priceVerbs[unit] {
			unit = ""
		}
		q := qty{val: v, word: unit}
		if unit != "" {
			q.unit = key(unit)
		}
		// price: "<item> стоит N", "цена <item> N", "<item> за N", "по N"
		isPrice, item := false, ""
		for j := i - 1; j >= 0; j-- {
			switch {
			case priceVerbs[ts[j]]:
				isPrice = true
				if it, _ := prevWord(ts, j-1); it != "" {
					item = it
				}
			case priceNouns[ts[j]]:
				isPrice = true
				if it, _ := nextWord(ts, j+1); it != "" && it != t {
					item = it
				}
			case ts[j] == "за" && j == i-1 || ts[j] == "по" && j == i-1:
				isPrice = true
				if it, _ := prevWord(ts, j-1); it != "" {
					item = it
				}
			}
			if isPrice {
				break
			}
		}
		if isPrice && item != "" && !haveVerbs[item] {
			k := key(item)
			w.price[k] = q
			w.priceTxt[k] = item
			continue
		}
		// possession / stock: "у <owner> (есть) N <unit>", "<owner> имеет N", "в магазине (есть) N <items>"
		owner, place := "", false
		for j := i - 1; j >= 0; j-- {
			if ts[j] == "у" && j+1 < i {
				owner = ts[j+1]
				break
			}
			if (ts[j] == "в" || ts[j] == "на") && j+1 < i && placeWords[ts[j+1]] {
				place = true
				break
			}
			if haveVerbs[ts[j]] && j > 0 && isWord(ts[j-1]) && ts[j-1] != "у" {
				if p, _ := prevWord(ts, j-1); p != "" && !placeWords[p] {
					owner = p
				}
			}
		}
		switch {
		case place && unit != "":
			w.stock[q.unit] = v
			w.stockTxt[q.unit] = unit
		case owner != "":
			k := w.addOwner(owner)
			w.have[k] = append(w.have[k], q)
		}
	}
}

func prevWord(ts []string, i int) (string, int) {
	for j := i; j >= 0; j-- {
		if isWord(ts[j]) && !fillers[ts[j]] {
			if ts[j] == "у" || ts[j] == "в" || ts[j] == "и" || ts[j] == "а" {
				return "", -1
			}
			return ts[j], j
		}
	}
	return "", -1
}

// SolveFacts answers purchase/affordability questions from explicit facts. Returns nil when the
// question is not of this kind.
func SolveFacts(state, question string) *FactAnswer {
	fa := solvePurchase(state, question)
	if fa == nil || fa.Answer == "unknown" {
		if ev := SolveEvents(state, question); ev != nil && (fa == nil || ev.Answer != "unknown") {
			return ev
		}
	}
	return fa
}

func solvePurchase(state, question string) *FactAnswer {
	q := factClauses(question)
	// the question may itself carry facts ("У Пети 5 рублей. Может ли он купить мяч за 10?")
	var qTs []string
	for _, c := range q {
		if strings.Contains(" "+strings.Join(c, " ")+" ", " ли ") || strings.HasPrefix(c[0], "кто") || strings.HasPrefix(c[0], "хват") || strings.HasPrefix(c[0], "can") {
			qTs = c
		}
	}
	if qTs == nil && len(q) > 0 {
		qTs = q[len(q)-1]
	}
	bi := -1
	enough := false
	for i, t := range qTs {
		if buyVerbs[t] {
			bi = i
		}
		if strings.HasPrefix(t, "хват") || strings.HasPrefix(t, "достаточно") {
			enough = true
		}
	}
	if bi < 0 && enough {
		return solveEnough(state, question, qTs)
	}
	if bi < 0 {
		return nil
	}
	w := &world{have: map[string][]qty{}, ownerTxt: map[string]string{}, price: map[string]qty{}, priceTxt: map[string]string{}, stock: map[string]float64{}, stockTxt: map[string]string{}}
	for _, c := range factClauses(state) {
		w.read(c)
	}
	for _, c := range q { // facts inside the question too, incl. "купить грушу за 5 яблок"
		w.read(c)
	}
	// what and how many
	count, item := 1.0, ""
	for j := bi + 1; j < len(qTs); j++ {
		if v, ok := isNumber(qTs[j]); ok {
			count = v
			continue
		}
		if isWord(qTs[j]) && !fillers[qTs[j]] && qTs[j] != "на" && qTs[j] != "себе" {
			item = qTs[j]
			break
		}
	}
	// who
	who := ""
	ask := false
	for j := 0; j < bi; j++ {
		t := qTs[j]
		if t == "кто" || t == "кто-то" || t == "кто-нибудь" || t == "who" || t == "anyone" {
			ask = true
		}
		if t == "у" && j+1 < bi {
			who = qTs[j+1]
		}
	}
	if who == "" && !ask {
		for j := bi - 1; j >= 0; j-- {
			t := qTs[j]
			if isWord(t) && !map[string]bool{"ли": true, "может": true, "могут": true, "сможет": true, "можно": true, "хватит": true, "хватает": true, "ему": true, "ей": true, "денег": true, "чтобы": true}[t] {
				who = t
				break
			}
		}
	}
	fa := &FactAnswer{Answer: "unknown", Solver: "facts"}
	fa.Reasoning = append(fa.Reasoning, w.notes...)
	if item == "" {
		fa.Reasoning = append(fa.Reasoning, "не понял, что именно покупают")
		return fa
	}
	ik := key(item)
	// stock limit
	if s, ok := w.stock[ik]; ok && count > s {
		fa.Answer, fa.Confidence = "no", 0.95
		fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("в наличии только %s %s, а нужно %s — купить столько нельзя никому", fmtNum(s), w.stockTxt[ik], fmtNum(count)))
		return fa
	}
	pr, ok := w.price[ik]
	if !ok {
		fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("цена «%s» в условии не указана", item))
		return fa
	}
	need := pr.val * count
	calc := fmtNum(pr.val)
	if count != 1 {
		calc = fmt.Sprintf("%s × %s = %s", fmtNum(count), fmtNum(pr.val), fmtNum(need))
	}
	if w.discount != nil {
		need = round9(need * (1 - *w.discount/100))
		calc += fmt.Sprintf(", со скидкой %s%% = %s", fmtNum(*w.discount), fmtNum(need))
	}
	check := func(ok string) (float64, string, bool) {
		var total float64
		var unit string
		found := false
		for _, h := range w.have[ok] {
			if pr.unit == "" || h.unit == "" || h.unit == pr.unit {
				total += h.val
				found = true
				if unit == "" {
					unit = h.word
				}
			}
		}
		return total, unit, found
	}
	owners := w.owners
	if !ask {
		k := ""
		if who != "" && !pronouns[who] {
			k = key(who)
		} else if len(w.owners) == 1 {
			k = w.owners[0]
		}
		if _, ok := w.ownerTxt[k]; !ok {
			if len(w.owners) == 1 && (who == "" || pronouns[who]) {
				k = w.owners[0]
			} else {
				fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("в условии не сказано, сколько денег у «%s»", who))
				return fa
			}
		}
		owners = []string{k}
	}
	if len(owners) == 0 {
		fa.Reasoning = append(fa.Reasoning, "в условии не сказано, у кого сколько денег")
		return fa
	}
	unitW := pr.word
	yes := 0
	for _, k := range owners {
		total, u, found := check(k)
		if !found {
			fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("у «%s» нет суммы в тех же единицах, что цена (%s)", w.ownerTxt[k], pr.word))
			if !ask {
				return fa
			}
			continue
		}
		if unitW == "" {
			unitW = u
		}
		if total >= need {
			yes++
			fa.Who = append(fa.Who, w.ownerTxt[k])
			fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("у «%s» %s %s ≥ нужно %s (%s) — хватает", w.ownerTxt[k], fmtNum(total), u, fmtNum(need), calc))
		} else {
			fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("у «%s» %s %s < нужно %s (%s) — не хватает %s", w.ownerTxt[k], fmtNum(total), u, fmtNum(need), calc, fmtNum(round9(need-total))))
		}
	}
	fa.Confidence = 0.95
	if yes > 0 {
		fa.Answer = "yes"
	} else {
		fa.Answer = "no"
		if ask {
			fa.Who = []string{}
			fa.Reasoning = append(fa.Reasoning, "никто не может")
		}
	}
	return fa
}

type counted struct {
	val  float64
	keys map[string]bool
	text string
}

var quantFill = map[string]bool{"всех": true, "всем": true, "каждого": true, "каждому": true, "нас": true, "них": true, "весь": true, "всю": true, "все": true}

// countFacts extracts "N <unit> <noun>" and "<noun> <verb> N" quantities.
func countFacts(s string) []counted {
	var out []counted
	for _, ts := range factClauses(s) {
		for i, t := range ts {
			v, ok := isNumber(t)
			if !ok || (i+1 < len(ts) && ts[i+1] == "%") || (i > 0 && ts[i-1] == "по") {
				continue
			}
			c := counted{val: v, keys: map[string]bool{}}
			var words []string
			for j := i + 1; j < len(ts) && j <= i+2; j++ {
				if !isWord(ts[j]) || stopWords[ts[j]] || quantFill[ts[j]] {
					break
				}
				words = append(words, ts[j])
			}
			if len(words) == 0 { // "друзей пришло 8"
				for j := i - 1; j >= 0 && j >= i-2; j-- {
					if isWord(ts[j]) && !stopWords[ts[j]] {
						words = append([]string{ts[j]}, words...)
					}
				}
			}
			for _, w := range words {
				c.keys[key(w)] = true
			}
			c.text = fmtNum(v) + " " + strings.Join(words, " ")
			if len(words) > 0 {
				out = append(out, c)
			}
		}
	}
	return out
}

func perEach(s string) (float64, bool) {
	for _, ts := range factClauses(s) {
		for i, t := range ts {
			if t == "по" && i+1 < len(ts) {
				if v, ok := isNumber(ts[i+1]); ok {
					return v, true
				}
			}
		}
	}
	return 1, false
}

// solveEnough: "Хватит ли пиццы на всех друзей?" — resource count vs consumers × amount each.
func solveEnough(state, question string, qTs []string) *FactAnswer {
	fa := &FactAnswer{Answer: "unknown", Solver: "facts"}
	res, cons := "", ""
	for i, t := range qTs {
		if t == "ли" || strings.HasPrefix(t, "хват") || strings.HasPrefix(t, "достаточно") {
			if w, _ := nextWord(qTs, i+1); w != "" && res == "" && w != "ли" && w != "на" && w != "для" && !strings.HasPrefix(w, "хват") {
				res = w
			}
		}
		if (t == "на" || t == "для") && cons == "" {
			for j := i + 1; j < len(qTs); j++ {
				if isWord(qTs[j]) && !quantFill[qTs[j]] && !fillers[qTs[j]] {
					cons = qTs[j]
					break
				}
			}
		}
	}
	if res == "" || cons == "" {
		return nil
	}
	facts := countFacts(state + ". " + question)
	var r, c *counted
	for i := range facts {
		f := &facts[i]
		if f.keys[key(res)] && r == nil {
			r = f
		} else if f.keys[key(cons)] && c == nil {
			c = f
		}
	}
	if r == nil || c == nil {
		miss := res
		if r != nil {
			miss = cons
		}
		fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("в условии нет количества для «%s»", miss))
		return fa
	}
	per, explicit := perEach(state)
	need := c.val * per
	how := fmt.Sprintf("нужно %s × %s = %s", fmtNum(c.val), fmtNum(per), fmtNum(need))
	if !explicit {
		how = fmt.Sprintf("нужно %s (по одному на каждого — норма в условии не указана)", fmtNum(need))
	}
	fa.Confidence = 0.95
	if !explicit {
		fa.Confidence = 0.9
	}
	if r.val >= need {
		fa.Answer = "yes"
		fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("есть %s, %s — хватает, останется %s", r.text, how, fmtNum(round9(r.val-need))))
	} else {
		fa.Answer = "no"
		fa.Reasoning = append(fa.Reasoning, fmt.Sprintf("есть %s, %s — не хватает %s", r.text, how, fmtNum(round9(need-r.val))))
	}
	return fa
}
