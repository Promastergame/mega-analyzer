package experts

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"decisionai/s1"
)

// measureAnswer covers deterministic numeric situations beyond have/need:
// value vs limit (thresholds), list sizes, and "which option is cheaper/faster".
var (
	limitStems = []string{"лими", "поро", "макс", "пред", "норм", "limi", "max", "thre", "cap"}
	valueStems = []string{"знач", "теку", "пока", "факт", "valu", "curr", "read", "actu"}
	qOverRe    = regexp.MustCompile(`превыш|перегр|слишком|выше (лимита|нормы|порога|допуст)|за предел|exceed|over the limit|too (high|much|many)|overload`)
	qOkRe      = regexp.MustCompile(`в норме|в пределах|допустим|нормальн|within (the )?limit|in range|is it ok`)
	limTextRe  = regexp.MustCompile(`(?i)(лимит|порог|максимум|допустимый максимум|предел|норма|limit|max(?:imum)?)[^\d\n]{0,12}(\d+(?:[.,]\d+)?)`)
	valTextRe  = regexp.MustCompile(`(?i)(показывает|значение|сейчас|текущ[а-я]*|reading|value|is)[^\d\n]{0,25}(\d+(?:[.,]\d+)?)`)
	moreThanRe = regexp.MustCompile(`(?:больше|более|свыше|more than|over)\s*(?:чем\s*)?(\d+)`)
	emptyRe    = regexp.MustCompile(`пуст|empty|ни одного|нет ни`)
	minWordRe  = regexp.MustCompile(`дешевле|дешёвый|дешевый|самый дешев|легче|меньше|ниже|короче|медленнее|cheap|light|small|low|short`)
	maxWordRe  = regexp.MustCompile(`дороже|быстрее|тяжелее|больше|выше|вместительн|длиннее|рейтинг|faster|heav|bigg|larg|high|more|rating|expensive`)
)

func valueLimit(state any, st string) (val, lim float64, ev string, ok bool) {
	var vs, ls []string
	var vv, lv []float64
	for k, v := range fields(state) {
		f, isNum := num(v)
		if !isNum {
			continue
		}
		last := k[strings.LastIndex(k, ".")+1:]
		l, x := hasStem(last, limitStems), hasStem(last, valueStems)
		switch {
		case l && !x:
			ls, lv = append(ls, last), append(lv, f)
		case x && !l:
			vs, vv = append(vs, last), append(vv, f)
		}
	}
	if len(vv) == 1 && len(lv) == 1 {
		return vv[0], lv[0], fmt.Sprintf("%s = %g, %s = %g", vs[0], vv[0], ls[0], lv[0]), true
	}
	lm := limTextRe.FindAllStringSubmatch(st, -1)
	if len(lm) == 1 {
		l, _ := num(lm[0][2])
		// value: the first number in the text that is not the limit
		for _, m := range regexp.MustCompile(`\d+(?:[.,]\d+)?`).FindAllString(st, -1) {
			if x, _ := num(m); x != l {
				return x, l, fmt.Sprintf("в тексте: значение %g, лимит %g", x, l), true
			}
		}
	}
	return 0, 0, "", false
}

var thanRe = regexp.MustCompile(`^\s*([^\s,]+)\s+(.{3,40}?),?\s+чем\s+([^\s?,]+)\s*\??\s*$`)

// valueFor finds the single number attached to name: a numeric field whose path
// contains name as a token, else "name … 42" in the text.
func valueFor(state any, st, name string) (float64, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if len([]rune(name)) < 2 {
		return 0, false
	}
	found, val := 0, 0.0
	for k, v := range fields(state) {
		f, isNum := num(v)
		if !isNum {
			continue
		}
		for _, p := range strings.FieldsFunc(strings.ToLower(k), func(r rune) bool { return r == '.' || r == '_' || r == ' ' }) {
			if p == name {
				val, found = f, found+1
				break
			}
		}
	}
	if found == 1 {
		return val, true
	}
	if found > 1 {
		return 0, false
	}
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(name) + `[»"']?[^\d\n.;]{0,25}?(\d+(?:[.,]\d+)?)`)
	ms := re.FindAllStringSubmatch(st, -1)
	if len(ms) != 1 {
		return 0, false
	}
	return num(ms[0][1])
}

func listLen(state any) (int, string, bool) {
	obj, ok := state.(map[string]any)
	if !ok {
		return 0, "", false
	}
	n, key, found := 0, "", false
	for k, v := range obj {
		if l, isList := v.([]any); isList {
			if found {
				return 0, "", false
			}
			n, key, found = len(l), k, true
		}
	}
	return n, key, found
}

func measureAnswer(state any, st string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	instr := strings.ToLower(q.Instr)
	mk := func(yes bool, ev string) (s1.ExpertAnswer, bool) {
		p := 0.06
		if yes {
			p = 0.94
		}
		return s1.ExpertAnswer{Probs: []float64{p}, Evidence: []string{ev}, Source: "quantity-rule", Calibrated: true}, true
	}
	switch q.Type {
	case s1.TypeNoul:
		over, okq := qOverRe.MatchString(instr), qOkRe.MatchString(instr)
		if over != okq {
			if v, l, ev, ok := valueLimit(state, st); ok {
				ex := v > l
				return mk(ex == over, fmt.Sprintf("%s → %s", ev, map[bool]string{true: "превышение", false: "в пределах"}[ex]))
			}
		}
		if m := thanRe.FindStringSubmatch(instr); m != nil {
			lo, hi := minWordRe.MatchString(m[2]), maxWordRe.MatchString(m[2])
			a, okA := valueFor(state, st, m[1])
			b, okB := valueFor(state, st, m[3])
			if lo != hi && okA && okB && a != b {
				return mk(lo && a < b || hi && a > b, fmt.Sprintf("%s = %g, %s = %g", m[1], a, m[3], b))
			}
		}
		if n, key, ok := listLen(state); ok {
			if m := moreThanRe.FindStringSubmatch(instr); m != nil {
				k, _ := num(m[1])
				return mk(float64(n) > k, fmt.Sprintf("в списке %s %d элементов", key, n))
			}
			if emptyRe.MatchString(instr) {
				return mk(n == 0, fmt.Sprintf("в списке %s %d элементов", key, n))
			}
		}
	case s1.TypeChoice:
		lo, hi := minWordRe.MatchString(instr), maxWordRe.MatchString(instr)
		if lo == hi || len(q.Options) < 2 {
			return s1.ExpertAnswer{}, false
		}
		vals := make([]float64, len(q.Options))
		for i, o := range q.Options {
			v, ok := valueFor(state, st, o.Key)
			if !ok {
				return s1.ExpertAnswer{}, false
			}
			vals[i] = v
		}
		best := 0
		for i := range vals {
			if lo && vals[i] < vals[best] || hi && vals[i] > vals[best] {
				best = i
			}
		}
		for i := range vals {
			if i != best && vals[i] == vals[best] {
				return s1.ExpertAnswer{}, false
			}
		}
		a := peaked(len(q.Options), best, 0.9, fmt.Sprintf("%s = %g — %s", q.Options[best].Key, vals[best], map[bool]string{true: "минимум", false: "максимум"}[lo]))
		a.Source = "quantity-rule"
		return a, true
	}
	return s1.ExpertAnswer{}, false
}

var _ = math.Inf
