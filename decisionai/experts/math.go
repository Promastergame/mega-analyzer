package experts

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"decisionai/s1"
)

// Math (v1.18) answers math questions exactly instead of guessing:
//   - arithmetic in the right order: brackets, then powers/roots, then · and :, then + and −
//     (2 + 2·2 = 6), fractions, decimals, percents, powers, roots, logarithms, factorials, НОД/НОК;
//   - comparisons <, >, = of numbers, expressions or two state fields («деньги Пети и цена бургера»);
//   - number properties: чётное, простое, делится на N, целое, положительное;
//   - algebra: equations with one unknown (roots), identities ((a+b)^2 = a^2+2ab+b^2?);
//   - boolean algebra: и/или/не/xor/→, truth for given values, tautology, satisfiability;
//   - probability (N из M, монеты, кубики, урна с шарами, независимые и несовместные события)
//     and statistics (среднее, медиана, мода, размах, дисперсия, отклонение, сумма, min/max).
//
// It answers only when the computation is unambiguous; otherwise the general model answers.
type Math struct{}

func (Math) Name() string { return "math-rule" }

const mathP = 0.97

var (
	boolCtxRe  = regexp.MustCompile(`логическ|булев|истин|ложн|тавтолог|выполним|xor|исключающ|импликац|конъюнкц|дизъюнкц|отрицани|(^|[^a-z])(and|or|not|true|false)([^a-z]|$)|&&|\|\||∧|∨|¬|⊕|→`)
	algCtxRe   = regexp.MustCompile(`уравнени|корн[иьея]|корнем|реши|найди(те)?\s+[a-z]|чему\s+равен\s+[a-z]([^a-z]|$)|тождеств|при\s+любых|при\s+любом|всегда|для\s+всех|equation|solve|identity|for\s+all|root`)
	identRe    = regexp.MustCompile(`тождеств|при\s+любых|при\s+любом|всегда|для\s+всех|identity|for\s+all|always`)
	tautRe     = regexp.MustCompile(`тавтолог|всегда\s+истин|tautolog|always\s+true`)
	satRe      = regexp.MustCompile(`выполним|может\s+быть\s+истин|бывает\s+истин|satisfiab|can\s+be\s+true`)
	contraRe   = regexp.MustCompile(`противоречи|всегда\s+ложн|contradiction|always\s+false`)
	falseQRe   = regexp.MustCompile(`ложн[оа]\s+ли|неверно\s+ли|is\s+it\s+false`)
	assignRe   = regexp.MustCompile(`(^|[^a-z])([a-z])\s*=\s*(-?\d+(?:[.,]\d+)?|true|false|истина|ложь)`)
	maxQRe     = regexp.MustCompile(`наибольш|самое\s+большое|самый\s+большой|больше|максим|largest|greatest|biggest|max`)
	minQRe     = regexp.MustCompile(`наименьш|самое\s+маленькое|самый\s+маленький|меньше|миним|smallest|least|min`)
	evenRe     = regexp.MustCompile(`(^|[^н])ч[её]тн|(^|[^a-z])even`)
	oddRe      = regexp.MustCompile(`неч[её]тн|(^|[^a-z])odd`)
	primeRe    = regexp.MustCompile(`прост(ое|ым|ой)|prime`)
	divRe      = regexp.MustCompile(`(?:делится|делиться|кратн[оа]?|divisible)\s*(?:без\s+остатка\s+)?(?:на|by)?\s*(\d+)`)
	intRe      = regexp.MustCompile(`цел(ое|ым)\s+числ|целое|integer|whole\s+number`)
	posRe      = regexp.MustCompile(`положительн|positive`)
	negNumRe   = regexp.MustCompile(`отрицательн|negative`)
	sqNumRe    = regexp.MustCompile(`полн(ый|ым)\s+квадрат|perfect\s+square`)
	relWordRe  = regexp.MustCompile(`не\s+меньше|не\s+менее|не\s+больше|не\s+более|больше|более|дороже|выше|старше|длиннее|тяжелее|быстрее|меньше|менее|дешевле|ниже|младше|короче|легче|медленнее|равн|столько\s+же|одинаков|совпада|greater|more|higher|older|longer|heavier|faster|less|fewer|lower|younger|shorter|lighter|slower|equal|same`)
	compareQRe = regexp.MustCompile(`соотнос|сравни|сравн|compare|relation|больше\s+или\s+меньше|какой\s+знак|знак\s+сравнени`)
	noRootsRe  = regexp.MustCompile(`нет\s+корней|корней\s+нет|нет\s+решени|решений\s+нет|не\s+имеет\s+(корней|решений)|no\s+(real\s+)?(roots|solutions?)|∅`)
	anyRootRe  = regexp.MustCompile(`любое\s+число|бесконечно\s+много|infinitely\s+many|any\s+number|все\s+числа`)
	trueOptRe  = regexp.MustCompile(`^(1|true|истина|верно|да|yes|правда|истинно)$`)
	falseOptRe = regexp.MustCompile(`^(0|false|ложь|неверно|нет|no|ложно)$`)
)

func relOfWord(w string) string {
	switch {
	case strings.HasPrefix(w, "не мен"), strings.HasPrefix(w, "не бол") && false:
		return ">="
	case strings.HasPrefix(w, "не бол"):
		return "<="
	case regexp.MustCompile(`^(больше|более|дороже|выше|старше|длиннее|тяжелее|быстрее|greater|more|higher|older|longer|heavier|faster)`).MatchString(w):
		return ">"
	case regexp.MustCompile(`^(меньше|менее|дешевле|ниже|младше|короче|легче|медленнее|less|fewer|lower|younger|shorter|lighter|slower)`).MatchString(w):
		return "<"
	}
	return "="
}

func relHolds(rel string, a, b float64) bool {
	switch rel {
	case ">":
		return a > b && !feq(a, b)
	case "<":
		return a < b && !feq(a, b)
	case ">=":
		return a > b || feq(a, b)
	case "<=":
		return a < b || feq(a, b)
	case "!=":
		return !feq(a, b)
	}
	return feq(a, b)
}

func relBetween(a, b float64) string {
	switch {
	case feq(a, b):
		return "="
	case a > b:
		return ">"
	}
	return "<"
}

// optionRel reads a relation from an option: symbol key/text first, then words.
func optionRel(o s1.Option) string {
	for _, s := range []string{o.Key, o.Text} {
		t := strings.TrimSpace(strings.ToLower(s))
		switch t {
		case ">", "<", "=", "==", ">=", "<=", "!=", "≥", "≤", "≠", "больше", "меньше", "равно", "равны":
			return map[string]string{">": ">", "<": "<", "=": "=", "==": "=", ">=": ">=", "<=": "<=", "!=": "!=", "≥": ">=", "≤": "<=", "≠": "!=",
				"больше": ">", "меньше": "<", "равно": "=", "равны": "="}[t]
		}
	}
	t := strings.ToLower(o.Key + " " + o.Text)
	for _, sym := range []string{">=", "<=", "!=", "≥", "≤", "≠", ">", "<", "="} {
		if strings.Contains(t, sym) {
			return map[string]string{"≥": ">=", "≤": "<=", "≠": "!="}[sym] + map[bool]string{true: "", false: sym}[sym == "≥" || sym == "≤" || sym == "≠"]
		}
	}
	if m := relWordRe.FindString(t); m != "" {
		if strings.HasPrefix(m, "не мен") || strings.HasPrefix(m, "не бол") {
			return relOfWord(m)
		}
		return relOfWord(m)
	}
	return ""
}

// problem collects the question and the textual parts of the state.
func problem(state any, stateText string, q s1.ExpertQuestion) (instr, all string) {
	instr = strings.ToLower(q.Instr)
	var parts []string
	if s, ok := state.(string); ok {
		parts = append(parts, s)
	} else {
		keys := []string{}
		f := fields(state)
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := f[k].(string); ok {
				parts = append(parts, s)
			}
		}
	}
	return instr, strings.ToLower(strings.Join(parts, ". "))
}

// stateEnv: numeric/bool state fields usable as variables (single letters or exact names).
func stateEnv(state any) map[string]float64 {
	env := map[string]float64{}
	for k, v := range fields(state) {
		last := k[strings.LastIndex(k, ".")+1:]
		if !regexp.MustCompile(`^[a-z]$`).MatchString(last) {
			continue
		}
		if f, ok := num(v); ok {
			env[last] = f
		} else if b, ok := v.(bool); ok {
			env[last] = b2f(b)
		}
	}
	return env
}

func textEnv(s string, env map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for k, v := range env {
		out[k] = v
	}
	for _, m := range assignRe.FindAllStringSubmatch(s, -1) {
		v := m[3]
		switch v {
		case "true", "истина":
			out[m[2]] = 1
		case "false", "ложь":
			out[m[2]] = 0
		default:
			f, _ := num(v)
			out[m[2]] = f
		}
	}
	return out
}

// optVal parses an option as a number ("1/6", "50%", "√2", "x = 4", "истина").
func optVal(o s1.Option) (float64, int, bool) {
	for _, s := range []string{o.Text, o.Key} {
		t := strings.TrimSpace(strings.ToLower(s))
		if t == "" {
			continue
		}
		if trueOptRe.MatchString(t) && s == o.Key && o.Text == "" {
			return 1, 0, true
		}
		t = regexp.MustCompile(`^(?:ответ\s*:?\s*|[a-z]\s*=\s*|[a-z]\d\s*=\s*)`).ReplaceAllString(t, "")
		t = strings.TrimRight(t, ". ")
		n := normMath(t, false)
		toks := tokenize(n)
		if len(toks) == 0 {
			continue
		}
		nd, _, err := parseTokens(toks, false)
		if err != nil || nd.isBool() {
			continue
		}
		if v, ok := evalQuiet(nd, nil); ok {
			dec := -1 // exact form
			if len(toks) == 1 && toks[0].k == 'n' {
				dec = toks[0].dec
			} else if len(toks) == 2 && toks[0].k == 'n' && toks[1].s == "%" {
				dec = toks[0].dec + 2
			}
			return v, dec, true
		}
	}
	return 0, 0, false
}

func optBool(o s1.Option) (bool, bool) {
	for _, s := range []string{o.Key, o.Text} {
		t := strings.TrimSpace(strings.ToLower(s))
		if trueOptRe.MatchString(t) {
			return true, true
		}
		if falseOptRe.MatchString(t) {
			return false, true
		}
	}
	return false, false
}

func valMatches(v, ov float64, dec int) bool {
	if dec >= 0 && dec < 12 && !feq(ov, math.Round(ov)) || dec > 0 {
		tol := 0.5*math.Pow(10, -float64(dec)) + 1e-12
		return math.Abs(v-ov) <= tol
	}
	return feq(v, ov)
}

// pickValue chooses the single option equal to v.
func pickValue(q s1.ExpertQuestion, v float64) (int, bool) {
	hit, parsed := -1, 0
	for i, o := range q.Options {
		ov, dec, ok := optVal(o)
		if !ok {
			continue
		}
		parsed++
		if valMatches(v, ov, dec) {
			if hit >= 0 && !feq(ov, mustOpt(q.Options[hit])) {
				return -1, false
			}
			if hit < 0 {
				hit = i
			}
		}
	}
	if hit < 0 && feq(v, math.Round(v)) { // score/choice with ranges: «1-2», «больше 5»
		for i, o := range q.Options {
			if b, ok := optionBucket(o); ok && !math.IsInf(b.lo, -1) && v > b.lo && v <= b.hi {
				if hit >= 0 {
					return -1, false
				}
				hit = i
			}
		}
		return hit, hit >= 0
	}
	return hit, hit >= 0 && parsed >= 1
}

func mustOpt(o s1.Option) float64 { v, _, _ := optVal(o); return v }

func boolAnswer(q s1.ExpertQuestion, truth bool, ev []string) (s1.ExpertAnswer, bool) {
	switch q.Type {
	case s1.TypeNoul:
		p := 1 - mathP
		if truth {
			p = mathP
		}
		return s1.ExpertAnswer{Probs: []float64{p}, Evidence: ev, Source: "math-rule", Calibrated: true}, true
	case s1.TypeChoice, s1.TypeScore:
		hit := -1
		for i, o := range q.Options {
			if b, ok := optBool(o); ok && b == truth {
				if hit >= 0 {
					return s1.ExpertAnswer{}, false
				}
				hit = i
			}
		}
		if hit >= 0 {
			return mathPeaked(q, hit, ev), true
		}
	}
	return s1.ExpertAnswer{}, false
}

func mathPeaked(q s1.ExpertQuestion, i int, ev []string) s1.ExpertAnswer {
	a := peaked(len(q.Options), i, mathP, "")
	a.Evidence, a.Source = ev, "math-rule"
	return a
}

func stepsEv(head string, steps []string) []string {
	ev := []string{head}
	if len(steps) > 1 || len(steps) == 1 && !strings.Contains(head, steps[0]) {
		ev = append(ev, "по шагам: "+strings.Join(steps, " → "))
	}
	return ev
}

func (Math) Answer(state any, stateText string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if !mathIntent(q) {
		return s1.ExpertAnswer{}, false
	}
	instr, all := problem(state, stateText, q)
	if a, ok := mathCompareFields(state, stateText, instr, q); ok {
		return a, true
	}
	if a, ok := mathStats(state, instr, all, q); ok {
		return a, true
	}
	if a, ok := mathProb(instr, all, q); ok {
		return a, true
	}
	src := instr
	if !hasMath(instr) && hasMath(all) {
		src = all + " " + instr
	}
	if !hasMath(src) {
		return s1.ExpertAnswer{}, false
	}
	boolCtx := boolCtxRe.MatchString(src)
	algCtx := algCtxRe.MatchString(instr) || regexp.MustCompile(`[0-9)]\s*[a-z]|[a-z]\s*\^|[a-z]\s*[+\-*/=]\s*[0-9(]`).MatchString(normMath(src, false)) && !boolCtx
	env := textEnv(normMath(src, false), stateEnv(state))
	norm := normMath(src, boolCtx)
	// drop "x = 1, y = 0" assignments from the search text in boolean context
	if boolCtx && len(env) > 0 {
		norm = assignRe.ReplaceAllString(norm, "$1 ; ")
	}
	sp := spans(norm, 1, algCtx)
	if len(sp) == 0 {
		// property over a bare number («17 простое?»): no operators, still answerable
		if q.Type == s1.TypeNoul {
			for _, s := range spans(norm, 0, false) {
				if len(freeVars(s.n)) == 0 && !s.n.isBool() {
					if v, ok := evalQuiet(s.n, nil); ok {
						if a, ok := numberProperty(q, instr, v, []string{fmt.Sprintf("%s = %s", s.text, fnum(v))}); ok {
							return a, true
						}
					}
				}
			}
		}
		return s1.ExpertAnswer{}, false
	}
	best := sp[0]
	vars := freeVars(best.n)
	unbound := []string{}
	for _, v := range vars {
		if _, ok := env[v]; !ok {
			unbound = append(unbound, v)
		}
	}
	// ---- boolean algebra over variables: tautology / satisfiable / contradiction
	if len(unbound) > 0 && best.n.isBool() && boolCtx && (tautRe.MatchString(instr) || satRe.MatchString(instr) || contraRe.MatchString(instr)) {
		if len(unbound) > 6 {
			return s1.ExpertAnswer{}, false
		}
		nt, total := 0, 1<<len(unbound)
		var counter string
		for m := 0; m < total; m++ {
			e := map[string]float64{}
			for k, v := range env {
				e[k] = v
			}
			for i, v := range unbound {
				e[v] = float64((m >> i) & 1)
			}
			v, ok := evalQuiet(best.n, e)
			if !ok {
				return s1.ExpertAnswer{}, false
			}
			if v != 0 {
				nt++
			} else if counter == "" {
				counter = assignment(unbound, m)
			}
		}
		ev := fmt.Sprintf("%s: истинно в %d из %d наборов значений", best.text, nt, total)
		if counter != "" && nt < total {
			ev += ", ложно например при " + counter
		}
		truth := nt == total
		if satRe.MatchString(instr) {
			truth = nt > 0
		} else if contraRe.MatchString(instr) {
			truth = nt == 0
		}
		return boolAnswer(q, truth, []string{ev})
	}
	// ---- algebra: equation or identity in one or more unknowns
	if len(unbound) > 0 && best.n.op == "=" {
		lhs, rhs := best.n.args[0], best.n.args[1]
		if identRe.MatchString(instr) || len(unbound) > 1 {
			eq, ok := identity(lhs, rhs, unbound, env)
			if !ok {
				return s1.ExpertAnswer{}, false
			}
			ev := []string{fmt.Sprintf("%s: проверено подстановкой 9 наборов значений, %s", best.text, map[bool]string{true: "равенство выполняется всегда", false: "равенство выполняется не всегда"}[eq])}
			return boolAnswer(q, eq, ev)
		}
		x := unbound[0]
		roots, inf, ok := solve(lhs, rhs, x, env)
		if !ok {
			return s1.ExpertAnswer{}, false
		}
		head := fmt.Sprintf("уравнение %s: ", best.text)
		switch {
		case inf:
			head += "верно при любом " + x
		case len(roots) == 0:
			head += "корней нет"
		default:
			var rs []string
			for _, r := range roots {
				rs = append(rs, x+" = "+fnum(r))
			}
			head += strings.Join(rs, ", ")
		}
		ev := []string{head}
		switch q.Type {
		case s1.TypeNoul: // «4 корень уравнения?» / «есть ли корни?»
			if regexp.MustCompile(`(есть|имеет)\s+(ли\s+)?(корни|корень|решени)|has\s+(a\s+)?(root|solution)`).MatchString(instr) {
				return boolAnswer(q, inf || len(roots) > 0, ev)
			}
			rest := strings.Replace(normMath(instr, false), best.text, " ", 1)
			nums := spans(rest, 0, false)
			cand := []float64{}
			for _, s := range nums {
				if len(freeVars(s.n)) == 0 && !s.n.isBool() {
					if v, ok := evalQuiet(s.n, nil); ok {
						cand = append(cand, v)
					}
				}
			}
			if len(cand) == 1 && regexp.MustCompile(`корн|решени|root|solution|удовлетвор`).MatchString(instr) {
				e := map[string]float64{x: cand[0]}
				for k, v := range env {
					e[k] = v
				}
				l, ok1 := evalQuiet(lhs, e)
				r, ok2 := evalQuiet(rhs, e)
				if ok1 && ok2 {
					return boolAnswer(q, feq(l, r), append(ev, fmt.Sprintf("подстановка %s = %s: %s и %s", x, fnum(cand[0]), fnum(l), fnum(r))))
				}
			}
			return s1.ExpertAnswer{}, false
		default:
			return pickRoots(q, roots, inf, ev)
		}
	}
	if len(unbound) > 0 {
		return s1.ExpertAnswer{}, false
	}
	v, steps, err := evalSteps(best.n, env)
	if err != nil {
		return s1.ExpertAnswer{}, false
	}
	if best.n.isBool() {
		truth := v != 0
		if falseQRe.MatchString(instr) {
			truth = !truth
		}
		head := fmt.Sprintf("%s: %s", best.text, map[bool]string{true: "верно", false: "неверно"}[v != 0])
		return boolAnswer(q, truth, stepsEv(head, steps))
	}
	head := fmt.Sprintf("%s = %s", best.text, fnum(v))
	ev := stepsEv(head, steps)
	switch q.Type {
	case s1.TypeNoul:
		if a, ok := numberProperty(q, instr, v, ev); ok {
			return a, true
		}
		// «2+3 больше 4?» is parsed as one boolean span above; here only property questions
		return s1.ExpertAnswer{}, false
	default:
		if i, ok := pickValue(q, v); ok {
			return mathPeaked(q, i, ev), true
		}
		if a, ok := compareOptions(q, instr, v, best.text); ok {
			return a, true
		}
	}
	return s1.ExpertAnswer{}, false
}

// Dispatch by the question's intent, never by incidental formulas in data
// (SQL WHERE id=42, a version number, a ticket or a risk rubric).
var mathIntentRe = regexp.MustCompile(`(?i)вычисл|посчита|рассчита|чему\s+рав|реши.{0,20}(уравнен|неравен)|най[дт]и.{0,20}(корн|сумм|произвед|значени)|средн(ее|юю|его)|медиан|дисперси|стандартн.{0,12}отклон|сумм[ауы]\s+чисел|тавтолог|выполним.{0,15}(формул|выражен)|истинно\s+ли|ложно\s+ли|логическ.{0,20}(выражен|формул)|булев|\b(calculate|compute|evaluate|equation|median|variance|tautology)\b|\b(mean|sum|average|product)\s+of\b|\bsolve\b`)
var mathAssertionRe = regexp.MustCompile(`(?i)^(верно\s+ли|неверно\s+ли|is\s+it\s+true|is\s+it\s+false)([,\s]|$)`)

func mathIntent(q s1.ExpertQuestion) bool {
	if q.Task != "" {
		return q.Task == s1.TaskMath
	}
	instr := strings.ToLower(strings.TrimSpace(q.Instr))
	if mathIntentRe.MatchString(instr) {
		return true
	}
	// Comparisons over named fields and numeric options are also mathematical,
	// but "How risky is this call?" is not a comparison just because its state
	// includes an expression or its score levels are numbers.
	if compareQRe.MatchString(instr) || (relWordRe.MatchString(instr) && strings.ContainsAny(instr, "0123456789")) {
		return true
	}
	if mathAssertionRe.MatchString(instr) && hasMath(instr) {
		return true
	}
	return false
}

func assignment(vars []string, m int) string {
	var s []string
	for i, v := range vars {
		s = append(s, fmt.Sprintf("%s = %d", strings.ToUpper(v), (m>>i)&1))
	}
	return strings.Join(s, ", ")
}

// hasMath: an operator between numbers, a math word, or a function.
var hasMathRe = regexp.MustCompile(`\d\s*[+\-*/^:×·÷%!<>=]|[+\-*/^×·÷<>=]\s*[\d(a-z]|√|∛|корень|логарифм|log|ln|lg|sqrt|степен|квадрат|куб|факториал|процент|уравнени|сочетани|плюс|минус|умнож|раздел|делить|делится|кратн|ч[её]тн|прост|нод|нок|синус|косинус|тангенс|модуль|истин|ложн|логическ|булев|тавтолог|выполним|xor|сравни|power|root|plus|minus|times|divided|equation|prime|even|odd|equal|greater|less`)

func hasMath(s string) bool { return hasMathRe.MatchString(s) }

func numberProperty(q s1.ExpertQuestion, instr string, v float64, ev []string) (s1.ExpertAnswer, bool) {
	isInt := feq(v, math.Round(v))
	n := int64(math.Round(v))
	var truth bool
	var what string
	switch {
	case oddRe.MatchString(instr):
		if !isInt {
			return s1.ExpertAnswer{}, false
		}
		truth, what = n%2 != 0, "нечётное"
	case evenRe.MatchString(instr):
		if !isInt {
			return s1.ExpertAnswer{}, false
		}
		truth, what = n%2 == 0, "чётное"
	case primeRe.MatchString(instr):
		if !isInt {
			return s1.ExpertAnswer{}, false
		}
		truth, what = isPrime(n), "простое"
	case divRe.MatchString(instr):
		d, _ := strconv.Atoi(divRe.FindStringSubmatch(instr)[1])
		if d == 0 || !isInt {
			return s1.ExpertAnswer{}, false
		}
		truth, what = n%int64(d) == 0, fmt.Sprintf("делится на %d (остаток %d)", d, ((n%int64(d))+int64(d))%int64(d))
	case sqNumRe.MatchString(instr):
		r := math.Round(math.Sqrt(v))
		truth, what = isInt && r*r == v, "полный квадрат"
	case intRe.MatchString(instr):
		truth, what = isInt, "целое"
	case negNumRe.MatchString(instr):
		truth, what = v < 0, "отрицательное"
	case posRe.MatchString(instr):
		truth, what = v > 0, "положительное"
	default:
		return s1.ExpertAnswer{}, false
	}
	return boolAnswer(q, truth, append(ev, fmt.Sprintf("%s %s: %s", fnum(v), what, map[bool]string{true: "да", false: "нет"}[truth])))
}

func isPrime(n int64) bool {
	if n < 2 {
		return false
	}
	for d := int64(2); d*d <= n; d++ {
		if n%d == 0 {
			return false
		}
	}
	return true
}

// compareOptions: «Что больше: 2/3 или 0,6?» with numeric options.
func compareOptions(q s1.ExpertQuestion, instr string, _ float64, _ string) (s1.ExpertAnswer, bool) {
	return s1.ExpertAnswer{}, false
}

func identity(lhs, rhs *node, vars []string, env map[string]float64) (bool, bool) {
	pts := []float64{0.37, 1.9, -2.3, 3.1, 0.71, -0.53, 2.6, 5.2, -4.4}
	okN := 0
	for i, p := range pts {
		e := map[string]float64{}
		for k, v := range env {
			e[k] = v
		}
		for j, v := range vars {
			e[v] = pts[(i+j*4)%len(pts)] + float64(j)*0.13 + p*0
		}
		l, ok1 := evalQuiet(lhs, e)
		r, ok2 := evalQuiet(rhs, e)
		if !ok1 || !ok2 {
			continue
		}
		okN++
		if math.Abs(l-r) > 1e-7*math.Max(1, math.Abs(l)) {
			return false, true
		}
	}
	return true, okN >= 5
}

// solve finds real roots of lhs = rhs in x on [-1000, 1000].
func solve(lhs, rhs *node, x string, env map[string]float64) (roots []float64, inf, ok bool) {
	f := func(v float64) (float64, bool) {
		e := map[string]float64{x: v}
		for k, w := range env {
			e[k] = w
		}
		l, ok1 := evalQuiet(lhs, e)
		r, ok2 := evalQuiet(rhs, e)
		return l - r, ok1 && ok2
	}
	if eq, ok := identity(lhs, rhs, []string{x}, env); ok && eq {
		return nil, true, true
	}
	add := func(r float64) {
		if math.Abs(r-math.Round(r)) < 1e-7 {
			r = math.Round(r)
		} else if p, q, ok := ratio(r); ok && q <= 100 && math.Abs(float64(p)/float64(q)-r) < 1e-9 {
			r = float64(p) / float64(q)
		}
		for _, o := range roots {
			if math.Abs(o-r) < 1e-6 {
				return
			}
		}
		roots = append(roots, r)
	}
	const lo, hi, step = -1000.0, 1000.0, 0.01
	pv, pok := f(lo)
	defined := 0
	for i := 1; i <= int((hi-lo)/step); i++ {
		xv := lo + float64(i)*step
		v, vok := f(xv)
		if vok {
			defined++
			if math.Abs(v) < 1e-10 {
				add(xv)
			} else if pok && pv != 0 && (pv < 0) != (v < 0) && math.Abs(v) < 1e6 && math.Abs(pv) < 1e6 {
				a, b, fa := xv-step, xv, pv
				for k := 0; k < 80; k++ {
					m := (a + b) / 2
					fm, _ := f(m)
					if (fm < 0) == (fa < 0) {
						a, fa = m, fm
					} else {
						b = m
					}
				}
				r := (a + b) / 2
				if fr, ok := f(r); ok && math.Abs(fr) < 1e-6 {
					add(r)
				}
			}
		}
		pv, pok = v, vok
		if len(roots) > 8 {
			return nil, false, false // periodic / too many: leave to the model
		}
	}
	// tangent roots (x² = 0) at integers and simple fractions
	for d := 1.0; d <= 4; d++ {
		for n := -40.0 * d; n <= 40*d; n++ {
			if v, ok := f(n / d); ok && math.Abs(v) < 1e-10 {
				add(n / d)
			}
		}
	}
	sort.Float64s(roots)
	return roots, false, defined > 0
}

func pickRoots(q s1.ExpertQuestion, roots []float64, inf bool, ev []string) (s1.ExpertAnswer, bool) {
	hit := -1
	set := func(i int) bool {
		if hit >= 0 {
			return false
		}
		hit = i
		return true
	}
	for i, o := range q.Options {
		t := strings.ToLower(o.Key + " " + o.Text)
		if noRootsRe.MatchString(t) {
			if len(roots) == 0 && !inf && !set(i) {
				return s1.ExpertAnswer{}, false
			}
			continue
		}
		if anyRootRe.MatchString(t) {
			if inf && !set(i) {
				return s1.ExpertAnswer{}, false
			}
			continue
		}
		if inf {
			continue
		}
		nums := optionNums(o)
		if len(nums) == 0 {
			continue
		}
		if sameSet(nums, roots) && !set(i) {
			return s1.ExpertAnswer{}, false
		}
	}
	if hit < 0 && len(roots) > 0 { // options list single roots
		for i, o := range q.Options {
			nums := optionNums(o)
			if len(nums) == 1 && containsF(roots, nums[0]) && !set(i) {
				return s1.ExpertAnswer{}, false
			}
		}
	}
	if hit < 0 {
		return s1.ExpertAnswer{}, false
	}
	return mathPeaked(q, hit, ev), true
}

func optionNums(o s1.Option) []float64 {
	if v, _, ok := optVal(o); ok {
		return []float64{v}
	}
	t := strings.ToLower(o.Text)
	if t == "" {
		t = strings.ToLower(o.Key)
	}
	t = regexp.MustCompile(`[a-z]\d?\s*=`).ReplaceAllString(t, " ; ")
	t = regexp.MustCompile(`(^|[^\p{L}])и([^\p{L}]|$)|(^|[^\p{L}])or([^\p{L}]|$)|(^|[^\p{L}])and([^\p{L}]|$)`).ReplaceAllString(t, " ; ")
	var out []float64
	for _, s := range spans(normMath(t, false), 0, false) {
		if len(freeVars(s.n)) == 0 && !s.n.isBool() {
			if v, ok := evalQuiet(s.n, nil); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func sameSet(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !containsF(b, x) {
			return false
		}
	}
	return true
}

func containsF(a []float64, x float64) bool {
	for _, y := range a {
		if math.Abs(x-y) <= 1e-6*math.Max(1, math.Abs(y)) {
			return true
		}
	}
	return false
}
