package experts

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"decisionai/s1"
)

// ---------- comparisons of two quantities ----------

type wpos struct {
	stem string
	pos  int
}

func instrStems(instr string) []wpos {
	var out []wpos
	i := 0
	for _, w := range strings.FieldsFunc(instr, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		r := []rune(w)
		if len(r) >= 3 {
			if len(r) > 4 {
				r = r[:4]
			}
			out = append(out, wpos{string(r), i})
		}
		i++
	}
	return out
}

type fieldHit struct {
	name string
	v    float64
	pos  int
}

// fieldPair finds numeric state fields named in the question, in order of mention.
func fieldPair(state any, instr string) []fieldHit {
	ws := instrStems(instr)
	var hits []fieldHit
	for k, v := range fields(state) {
		f, ok := num(v)
		if !ok {
			continue
		}
		last := k[strings.LastIndex(k, ".")+1:]
		best := -1
		for _, s := range qStems(last) {
			for _, w := range ws {
				if w.stem == s && (best < 0 || w.pos < best) {
					best = w.pos
				}
			}
		}
		if best >= 0 {
			hits = append(hits, fieldHit{last, f, best})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].pos < hits[j].pos || hits[i].pos == hits[j].pos && hits[i].name < hits[j].name
	})
	return hits
}

// twoValues: «сравни 3/4 и 0,7», two fields named in the question, or have/need from text.
func twoValues(state any, stateText, instr string) (a, b float64, ev string, ok bool) {
	var nums []mspan
	for _, s := range spans(normMath(instr, false), 0, false) {
		if len(freeVars(s.n)) == 0 && !s.n.isBool() {
			nums = append(nums, s)
		}
	}
	if len(nums) == 2 {
		sort.Slice(nums, func(i, j int) bool { return nums[i].lo < nums[j].lo })
		x, ok1 := evalQuiet(nums[0].n, nil)
		y, ok2 := evalQuiet(nums[1].n, nil)
		if ok1 && ok2 {
			return x, y, fmt.Sprintf("%s = %s, %s = %s", nums[0].text, fnum(x), nums[1].text, fnum(y)), true
		}
	}
	if len(nums) > 0 {
		return 0, 0, "", false
	}
	h := fieldPair(state, instr)
	if len(h) >= 2 && h[0].pos != h[1].pos && (len(h) == 2 || h[2].pos != h[1].pos) {
		return h[0].v, h[1].v, fmt.Sprintf("%s = %g, %s = %g", h[0].name, h[0].v, h[1].name, h[1].v), true
	}
	if have, need, e, ok := haveNeed(state, stateText, instr); ok {
		hp, np := -1, -1
		for _, w := range instrStems(instr) {
			if hp < 0 && hasStem(w.stem, haveStems) {
				hp = w.pos
			}
			if np < 0 && hasStem(w.stem, needStems) {
				np = w.pos
			}
		}
		if hp >= 0 && np >= 0 && hp != np {
			if hp < np {
				return have, need, e, true
			}
			return need, have, e, true
		}
	}
	return 0, 0, "", false
}

var relSym = map[string]string{">": ">", "<": "<", "=": "=", ">=": "≥", "<=": "≤", "!=": "≠"}

func mathCompareFields(state any, stateText, instr string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	switch q.Type {
	case s1.TypeChoice, s1.TypeScore:
		if len(q.Options) < 2 {
			return s1.ExpertAnswer{}, false
		}
		// numeric options + «что больше?»: pick the largest / smallest option value
		if a, ok := pickExtreme(q, instr); ok {
			return a, true
		}
		rels := map[string]bool{}
		for _, o := range q.Options {
			r := optionRel(o)
			if r == "" {
				return s1.ExpertAnswer{}, false
			}
			rels[r] = true
		}
		if len(rels) < 2 {
			return s1.ExpertAnswer{}, false
		}
		a, b, ev, ok := twoValues(state, stateText, instr)
		if !ok {
			return s1.ExpertAnswer{}, false
		}
		rel := relBetween(a, b)
		hit := -1
		for i, o := range q.Options {
			if optionRel(o) == rel {
				if hit >= 0 {
					return s1.ExpertAnswer{}, false
				}
				hit = i
			}
		}
		if hit < 0 {
			for i, o := range q.Options {
				if relHolds(optionRel(o), a, b) {
					if hit >= 0 {
						return s1.ExpertAnswer{}, false
					}
					hit = i
				}
			}
		}
		if hit < 0 {
			return s1.ExpertAnswer{}, false
		}
		return mathPeaked(q, hit, []string{fmt.Sprintf("%s → %s %s %s", ev, fnum(a), relSym[rel], fnum(b))}), true
	case s1.TypeNoul:
		m := relWordRe.FindString(instr)
		if m == "" || hasOpSpan(instr) {
			return s1.ExpertAnswer{}, false
		}
		rel := relOfWord(m)
		idx := strings.Index(instr, m)
		h := fieldPair(state, instr[:idx]+" "+strings.Repeat("_ ", 0)+instr[idx:])
		rest := normMath(instr[idx+len(m):], false)
		var after []float64
		for _, s := range spans(rest, 0, false) {
			if len(freeVars(s.n)) == 0 && !s.n.isBool() {
				if v, ok := evalQuiet(s.n, nil); ok {
					after = append(after, v)
				}
			}
		}
		var a, b float64
		var ev string
		switch {
		case len(h) == 2 && h[0].pos != h[1].pos && len(after) == 0:
			a, b, ev = h[0].v, h[1].v, fmt.Sprintf("%s = %g, %s = %g", h[0].name, h[0].v, h[1].name, h[1].v)
		case len(h) == 1 && len(after) == 1 && h[0].pos < len(strings.Fields(instr[:idx]))+1:
			a, b, ev = h[0].v, after[0], fmt.Sprintf("%s = %g", h[0].name, h[0].v)
		default:
			return s1.ExpertAnswer{}, false
		}
		truth := relHolds(rel, a, b)
		return boolAnswer(q, truth, []string{fmt.Sprintf("%s → %s %s %s: %s", ev, fnum(a), relSym[rel], fnum(b), map[bool]string{true: "верно", false: "неверно"}[truth])})
	}
	return s1.ExpertAnswer{}, false
}

var calcQRe = regexp.MustCompile(`сколько|чему\s+равн|найди|вычисли|посчитай|реши|how\s+much|what\s+is|calculate|compute`)

func pickExtreme(q s1.ExpertQuestion, instr string) (s1.ExpertAnswer, bool) {
	mx, mn := maxQRe.MatchString(instr), minQRe.MatchString(instr)
	if mx == mn || calcQRe.MatchString(instr) && !regexp.MustCompile(`какое|какая|какой|что|which`).MatchString(instr) {
		return s1.ExpertAnswer{}, false
	}
	vals := make([]float64, len(q.Options))
	for i, o := range q.Options {
		v, _, ok := optVal(o)
		if !ok {
			return s1.ExpertAnswer{}, false
		}
		vals[i] = v
	}
	best := 0
	for i, v := range vals {
		if mx && v > vals[best] || mn && v < vals[best] {
			best = i
		}
	}
	for i, v := range vals {
		if i != best && feq(v, vals[best]) {
			return s1.ExpertAnswer{}, false
		}
	}
	var parts []string
	for i, o := range q.Options {
		parts = append(parts, fmt.Sprintf("%s = %s", strings.TrimSpace(firstNonEmpty(o.Text, o.Key)), fnum(vals[i])))
	}
	word := "наибольшее"
	if mn {
		word = "наименьшее"
	}
	return mathPeaked(q, best, []string{strings.Join(parts, "; ") + " → " + word + ": " + firstNonEmpty(q.Options[best].Text, q.Options[best].Key)}), true
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func hasOpSpan(instr string) bool {
	for _, s := range spans(normMath(instr, false), 1, false) {
		if len(freeVars(s.n)) == 0 {
			return true
		}
	}
	return false
}

// relNumber: «вероятность больше 0,5?», «среднее меньше 3?» → (rel, 0.5).
func relNumber(instr string) (string, float64, bool) {
	m := relWordRe.FindStringIndex(instr)
	if m == nil {
		return "", 0, false
	}
	rel := relOfWord(instr[m[0]:m[1]])
	for _, s := range spans(normMath(instr[m[1]:], false), 0, false) {
		if len(freeVars(s.n)) == 0 && !s.n.isBool() {
			if v, ok := evalQuiet(s.n, nil); ok {
				return rel, v, true
			}
		}
	}
	return "", 0, false
}

func answerValue(q s1.ExpertQuestion, instr string, v float64, ev []string) (s1.ExpertAnswer, bool) {
	if q.Type == s1.TypeNoul {
		if rel, x, ok := relNumber(instr); ok {
			t := relHolds(rel, v, x)
			return boolAnswer(q, t, append(ev, fmt.Sprintf("%s %s %s: %s", fnum(v), relSym[rel], fnum(x), map[bool]string{true: "верно", false: "неверно"}[t])))
		}
		return s1.ExpertAnswer{}, false
	}
	if i, ok := pickValue(q, v); ok {
		return mathPeaked(q, i, ev), true
	}
	return s1.ExpertAnswer{}, false
}

// ---------- statistics ----------

var (
	stMean   = regexp.MustCompile(`средн(ее|его|ий|яя|ем)|mean|average`)
	stMedian = regexp.MustCompile(`медиан|median`)
	stMode   = regexp.MustCompile(`(^|[^\p{L}])мод(а|у|ой|ы)([^\p{L}]|$)|(^|[^a-z])mode([^a-z]|$)`)
	stRange  = regexp.MustCompile(`размах|(^|[^a-z])range([^a-z]|$)`)
	stVar    = regexp.MustCompile(`дисперси|variance`)
	stStd    = regexp.MustCompile(`стандартн\S*\s+отклонени|среднеквадратичн|(^|[^a-z])std|standard\s+deviation`)
	stSum    = regexp.MustCompile(`сумм[ауые]|(^|[^a-z])sum([^a-z]|$)|(^|[^a-z])total`)
	stMax    = regexp.MustCompile(`наибольш|максимальн|максимум|(^|[^a-z])max(imum)?([^a-z]|$)|largest`)
	stMin    = regexp.MustCompile(`наименьш|минимальн|минимум|(^|[^a-z])min(imum)?([^a-z]|$)|smallest`)
	stCount  = regexp.MustCompile(`сколько\s+(всего\s+)?чисел|количество\s+чисел|how\s+many\s+numbers`)
	stSample = regexp.MustCompile(`выборочн|исправленн|несмещ|sample`)
	listRe   = regexp.MustCompile(`-?\d+(?:[.,]\d+)?(?:(?:\s*;\s*|,\s+|\s+и\s+|\s+and\s+|\s+)-?\d+(?:[.,]\d+)?){2,}`)
	listCRe  = regexp.MustCompile(`-?\d+(?:\.\d+)?(?:,-?\d+(?:\.\d+)?){2,}`)
)

func numList(state any, instr, all string) ([]float64, string, bool) {
	var lists [][]float64
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for _, x := range t {
				walk(x)
			}
		case []any:
			var xs []float64
			for _, x := range t {
				f, ok := num(x)
				if !ok {
					xs = nil
					for _, y := range t {
						walk(y)
					}
					return
				}
				xs = append(xs, f)
			}
			if len(xs) >= 2 {
				lists = append(lists, xs)
			}
		}
	}
	walk(state)
	if len(lists) == 1 {
		return lists[0], "", true
	}
	for _, s := range []string{instr, all} {
		var m string
		if m = listCRe.FindString(s); m != "" && !strings.Contains(m, ", ") {
			var xs []float64
			for _, p := range strings.Split(m, ",") {
				f, _ := num(p)
				xs = append(xs, f)
			}
			return xs, m, true
		}
		if m = listRe.FindString(s); m != "" {
			parts := regexp.MustCompile(`\s*;\s*|,\s+|\s+и\s+|\s+and\s+|\s+`).Split(m, -1)
			var xs []float64
			for _, p := range parts {
				if f, ok := num(p); ok {
					xs = append(xs, f)
				}
			}
			if len(xs) >= 3 {
				return xs, m, true
			}
		}
	}
	return nil, "", false
}

func mathStats(state any, instr, all string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	kind := ""
	for _, k := range []struct {
		re   *regexp.Regexp
		name string
	}{{stStd, "std"}, {stVar, "var"}, {stMedian, "median"}, {stMode, "mode"}, {stRange, "range"}, {stMean, "mean"}, {stCount, "count"}, {stSum, "sum"}, {stMax, "max"}, {stMin, "min"}} {
		if k.re.MatchString(instr) {
			kind = k.name
			break
		}
	}
	if kind == "" {
		return s1.ExpertAnswer{}, false
	}
	xs, lit, ok := numList(state, instr, all)
	if !ok || len(xs) < 2 {
		return s1.ExpertAnswer{}, false
	}
	if (kind == "max" || kind == "min") && q.Type != s1.TypeNoul && pickExtremeOK(q) {
		return s1.ExpertAnswer{}, false // «какое число наибольшее?» with numeric options → pickExtreme
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	sum := 0.0
	for _, x := range s {
		sum += x
	}
	n := float64(len(s))
	mean := sum / n
	var v float64
	name := ""
	switch kind {
	case "mean":
		v, name = mean, "среднее"
	case "median":
		if len(s)%2 == 1 {
			v = s[len(s)/2]
		} else {
			v = (s[len(s)/2-1] + s[len(s)/2]) / 2
		}
		name = "медиана"
	case "mode":
		cnt := map[float64]int{}
		bestN := 0
		for _, x := range s {
			cnt[x]++
			if cnt[x] > bestN {
				bestN = cnt[x]
			}
		}
		var modes []float64
		for x, c := range cnt {
			if c == bestN {
				modes = append(modes, x)
			}
		}
		if len(modes) != 1 || bestN < 2 {
			return s1.ExpertAnswer{}, false
		}
		v, name = modes[0], "мода"
	case "range":
		v, name = s[len(s)-1]-s[0], "размах"
	case "sum":
		v, name = sum, "сумма"
	case "max":
		v, name = s[len(s)-1], "максимум"
	case "min":
		v, name = s[0], "минимум"
	case "count":
		v, name = n, "количество"
	case "var", "std":
		ss := 0.0
		for _, x := range s {
			ss += (x - mean) * (x - mean)
		}
		d := n
		if stSample.MatchString(instr) {
			d = n - 1
		}
		v, name = ss/d, "дисперсия"
		if kind == "std" {
			v, name = math.Sqrt(v), "стандартное отклонение"
		}
		if d == n-1 {
			name += " (выборочная)"
		}
	}
	_ = lit
	ev := []string{fmt.Sprintf("числа %s: %s = %s", joinNums(xs), name, fnum(v))}
	if kind == "mean" {
		ev = append(ev, fmt.Sprintf("%s : %g = %s", fnum(sum), n, fnum(v)))
	}
	rest := instr
	if lit != "" {
		rest = strings.Replace(instr, lit, " ", 1)
	}
	return answerValue(q, rest, v, ev)
}

func pickExtremeOK(q s1.ExpertQuestion) bool {
	for _, o := range q.Options {
		if _, _, ok := optVal(o); !ok {
			return false
		}
	}
	return false
}

// ---------- probability ----------

var (
	probQRe   = regexp.MustCompile(`вероятност|шанс|probability|chance|likelihood`)
	pEventRe  = regexp.MustCompile(`(?:p\s*\(\s*([a-zа-я])\s*\)|вероятность\s+(?:события\s+)?([a-zа-я]))\s*(?:=|равна|составляет|is)?\s*(\d+(?:[.,]\d+)?)\s*(%)?`)
	bothRe    = regexp.MustCompile(`обоих|оба\s|обе\s|одновременно|и\s+[a-zа-я]\s+и\s+[a-zа-я]|[a-zа-я]\s+и\s+[a-zа-я]\)|p\s*\(\s*[a-zа-я]\s*(и|∩|&|and)\s*[a-zа-я]\s*\)|both`)
	eitherRe  = regexp.MustCompile(`хотя\s+бы\s+одн|или|∪|either|at\s+least\s+one|p\s*\(\s*[a-zа-я]\s*(или|∪|\||or)\s*[a-zа-я]\s*\)`)
	neitherRe = regexp.MustCompile(`ни\s+одно|ни\s+одного|ни\s+то,?\s+ни\s+другое|neither|none`)
	notARe    = regexp.MustCompile(`не\s+произойд|не\s+наступ|противоположн|p\s*\(\s*(не|!|¬)\s*[a-zа-я]\s*\)|not\s+happen|complement`)
	indepRe   = regexp.MustCompile(`независим|independent`)
	exclRe    = regexp.MustCompile(`несовместн|mutually\s+exclusive|disjoint`)
	coinRe    = regexp.MustCompile(`монет|орл|ор[её]л|решк|coin|heads|tails`)
	tossRe    = regexp.MustCompile(`(\d+)\s*(?:раз|монет|броск|подбрасыван|times|coins|tosses|flips)`)
	exactRe   = regexp.MustCompile(`ровно\s+(\d+)|exactly\s+(\d+)`)
	atLeast1  = regexp.MustCompile(`хотя\s+бы\s+(один|одна|одну|1|раз)|at\s+least\s+(one|1|once)`)
	allRe     = regexp.MustCompile(`(^|[^\p{L}])(все|всё|каждый|только|all|every)([^\p{L}]|$)|оба\s+раза|both`)
	diceRe    = regexp.MustCompile(`кубик|игральн\S*\s+кост|(^|[^\p{L}])кост[ьи]|(^|[^a-z])(die|dice)([^a-z]|$)`)
	twoDiceRe = regexp.MustCompile(`(2|два|две)\s+(игральн\S*\s+)?(кубик|кост)|two\s+dice|2\s+dice|пар[ау]\s+кубиков`)
	sumNRe    = regexp.MustCompile(`сумм\S*\s+(?:очков\s+)?(?:будет\s+)?(=|>|<|>=|<=)?\s*(\d+)|sum\s+(?:is\s+|of\s+)?(=|>|<|>=|<=)?\s*(\d+)`)
	faceRe    = regexp.MustCompile(`(?:выпад\S*|выбросит\S*|get|roll\S*)\s+(?:число\s+|цифра\s+|a\s+)?(\d)|(шест[её]рк|пят[её]рк|четв[её]рк|тр[её]йк|двойк|единиц)`)
	colorRe   = regexp.MustCompile(`(\d+)\s+(красн|син|бел|ч[её]рн|зел[её]н|ж[её]лт|оранжев|фиолетов|розов|голуб|коричнев|сер|red|blue|white|black|green|yellow)\S*`)
	ofRe      = regexp.MustCompile(`(\d+(?:[.,]\d+)?)\s+из\s+(\d+(?:[.,]\d+)?)|(\d+)\s+(?:out\s+)?of\s+(\d+)`)
	fromRe    = regexp.MustCompile(`из\s+(\d+)\s+[\p{L}\s]{1,40}?(\d+)\s`)
	ofThemRe  = regexp.MustCompile(`(\d+)[^\d]{1,60}?(\d+)\s+из\s+них`)
)

var faceN = map[string]float64{"шест": 6, "пят": 5, "четв": 4, "тр": 3, "двойк": 2, "единиц": 1}

func mathProb(instr, all string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if !probQRe.MatchString(instr) {
		return s1.ExpertAnswer{}, false
	}
	txt := applyW(all+" . "+instr, numWords)
	ins := applyW(instr, numWords)
	p, ev, ok := probValue(txt, ins)
	if !ok {
		return s1.ExpertAnswer{}, false
	}
	return answerValue(q, ins, p, []string{ev + " = " + fnum(p)})
}

func probValue(txt, ins string) (float64, string, bool) {
	// explicit event probabilities
	ev := map[string]float64{}
	var order []string
	for _, m := range pEventRe.FindAllStringSubmatch(txt, -1) {
		name := m[1] + m[2]
		v, _ := num(m[3])
		if m[4] != "" {
			v /= 100
		}
		if _, seen := ev[name]; !seen && v >= 0 && v <= 1 {
			ev[name] = v
			order = append(order, name)
		}
	}
	if len(order) == 1 && notARe.MatchString(ins) {
		a := ev[order[0]]
		return 1 - a, fmt.Sprintf("P(не %s) = 1 − %s", strings.ToUpper(order[0]), fnum(a)), true
	}
	if len(order) == 2 {
		a, b := ev[order[0]], ev[order[1]]
		A, B := strings.ToUpper(order[0]), strings.ToUpper(order[1])
		switch {
		case neitherRe.MatchString(ins) && indepRe.MatchString(txt):
			return (1 - a) * (1 - b), fmt.Sprintf("независимые: (1 − %s)·(1 − %s)", fnum(a), fnum(b)), true
		case bothRe.MatchString(ins) && exclRe.MatchString(txt):
			return 0, "несовместные события вместе не происходят: 0", true
		case bothRe.MatchString(ins) && indepRe.MatchString(txt):
			return a * b, fmt.Sprintf("независимые: P(%s и %s) = %s·%s = %s", A, B, fnum(a), fnum(b), fnum(a*b)), true
		case eitherRe.MatchString(ins) && exclRe.MatchString(txt):
			return a + b, fmt.Sprintf("несовместные: P(%s или %s) = %s + %s", A, B, fnum(a), fnum(b)), true
		case eitherRe.MatchString(ins) && indepRe.MatchString(txt):
			return a + b - a*b, fmt.Sprintf("независимые: P(%s или %s) = %s + %s − %s·%s", A, B, fnum(a), fnum(b), fnum(a), fnum(b)), true
		}
		return 0, "", false
	}
	if len(order) > 0 {
		return 0, "", false
	}
	// dice
	if diceRe.MatchString(txt) {
		if twoDiceRe.MatchString(txt) {
			if regexp.MustCompile(`дубл|одинаков|same|double`).MatchString(ins) {
				return 6.0 / 36, "два кубика, одинаковые грани: 6 из 36", true
			}
			if m := sumNRe.FindStringSubmatch(ins); m != nil {
				rel, ns := m[1]+m[3], m[2]+m[4]
				if rel == "" {
					rel = "="
					if r := relWordRe.FindString(ins); r != "" && strings.Index(ins, r) < strings.Index(ins, ns) {
						rel = relOfWord(r)
					}
				}
				s, _ := num(ns)
				c := 0
				for i := 1; i <= 6; i++ {
					for j := 1; j <= 6; j++ {
						if relHolds(rel, float64(i+j), s) {
							c++
						}
					}
				}
				return float64(c) / 36, fmt.Sprintf("два кубика, сумма %s %s: %d из 36", relSym[rel], ns, c), true
			}
			return 0, "", false
		}
		cnt, what := -1, ""
		switch {
		case oddRe.MatchString(ins):
			cnt, what = 3, "нечётное (1, 3, 5)"
		case evenRe.MatchString(ins):
			cnt, what = 3, "чётное (2, 4, 6)"
		case primeRe.MatchString(ins):
			cnt, what = 3, "простое (2, 3, 5)"
		}
		if cnt < 0 {
			if r := relWordRe.FindString(ins); r != "" {
				if m := regexp.MustCompile(regexp.QuoteMeta(r) + `\s*(?:чем\s*)?(\d)`).FindStringSubmatch(ins); m != nil {
					x, _ := num(m[1])
					rel := relOfWord(r)
					cnt = 0
					for f := 1.0; f <= 6; f++ {
						if relHolds(rel, f, x) {
							cnt++
						}
					}
					what = fmt.Sprintf("%s %s", relSym[rel], m[1])
				}
			}
		}
		if cnt < 0 {
			if m := faceRe.FindStringSubmatch(ins); m != nil {
				cnt, what = 1, m[1]
				for k, v := range faceN {
					if m[2] != "" && strings.HasPrefix(m[2], k) {
						what = fmt.Sprint(v)
					}
				}
			}
		}
		if cnt >= 0 {
			return float64(cnt) / 6, fmt.Sprintf("кубик, %s: %d из 6", what, cnt), true
		}
		return 0, "", false
	}
	// coins
	if coinRe.MatchString(txt) {
		k := 1.0
		if m := tossRe.FindStringSubmatch(txt); m != nil {
			k, _ = num(m[1])
		}
		if k < 1 || k > 30 {
			return 0, "", false
		}
		total := math.Pow(2, k)
		switch {
		case exactRe.MatchString(ins):
			m := exactRe.FindStringSubmatch(ins)
			r, _ := num(m[1] + m[2])
			c := comb(k, r)
			return c / total, fmt.Sprintf("%g бросков, ровно %g: C(%g, %g) / 2^%g = %s / %s", k, r, k, r, k, fnum(c), fnum(total)), true
		case atLeast1.MatchString(ins):
			return 1 - 1/total, fmt.Sprintf("%g бросков, хотя бы один раз: 1 − 1/2^%g", k, k), true
		case k == 1 || allRe.MatchString(ins):
			return 1 / total, fmt.Sprintf("%g бросков, все одинаково: 1/2^%g", k, k), true
		}
		return 0, "", false
	}
	// urn with colours
	if cs := colorRe.FindAllStringSubmatch(txt, -1); len(cs) >= 2 {
		tot, seen := 0.0, map[string]float64{}
		for _, c := range cs {
			key := c[2][:min(len(c[2]), 6)]
			if _, ok := seen[key]; ok {
				continue
			}
			v, _ := num(c[1])
			seen[key] = v
			tot += v
		}
		var hit []string
		for k := range seen {
			if strings.Contains(ins, k) {
				hit = append(hit, k)
			}
		}
		if len(hit) == 1 && tot > 0 {
			n := seen[hit[0]]
			if regexp.MustCompile(`(^|[^\p{L}])не\s+` + hit[0]).MatchString(ins) {
				return (tot - n) / tot, fmt.Sprintf("не %s: (%g − %g) / %g", hit[0], tot, n, tot), true
			}
			return n / tot, fmt.Sprintf("%s: %g из %g", hit[0], n, tot), true
		}
		return 0, "", false
	}
	if m := ofThemRe.FindStringSubmatch(txt); m != nil {
		a, _ := num(m[2])
		b, _ := num(m[1])
		if b > 0 && a <= b {
			return a / b, fmt.Sprintf("%g из %g", a, b), true
		}
	}
	if ms := ofRe.FindAllStringSubmatch(txt, -1); len(ms) == 1 {
		a, _ := num(ms[0][1] + ms[0][3])
		b, _ := num(ms[0][2] + ms[0][4])
		if b > 0 && a <= b {
			return a / b, fmt.Sprintf("%g из %g", a, b), true
		}
	}
	if m := fromRe.FindStringSubmatch(txt); m != nil {
		b, _ := num(m[1])
		a, _ := num(m[2])
		if b > 0 && a <= b {
			return a / b, fmt.Sprintf("%g из %g", a, b), true
		}
	}
	return 0, "", false
}
