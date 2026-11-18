package experts

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"decisionai/s1"
)

// Quantity (v1.17) answers "is there enough X?" style questions by arithmetic instead of guessing:
// it finds what is available (have/balance/budget/stock…) and what is needed (price/cost/need…)
// in the structured state or in plain text, computes the shortfall, and maps it to
//   - noul: «хватает ли / может ли купить / enough / afford» (polarity from the question),
//   - score: options with numeric ranges («1-2», «3-5», «больше 5», «хватает полностью»),
//   - noul: a boolean state flag whose name is spelled out by the question (хватает_денег: false).
//
// Tiny neural encoders cannot compare 5 and 7 reliably; this expert can.
type Quantity struct{}

func (Quantity) Name() string { return "quantity-rule" }

var (
	haveStems = []string{"есть", "имее", "нали", "бала", "день", "денег", "нако", "бюдж", "оста", "дост", "кошел", "запа", "свобод",
		"have", "bala", "budg", "avai", "owne", "wall", "stoc", "free", "left", "cash", "fund", "save",
		"мест", "вмес", "слот", "capa", "seat", "slot"} // v1.17: capacity counts as "have"
	needStems = []string{"цена", "цены", "стои", "нужн", "треб", "сумм", "оплат", "надо", "пров", "pric", "cost", "need", "requ", "due", "fee", "amou", "targ", "необ",
		"пасс", "гост", "люде", "разм", "pass", "gues", "peop", "size"} // v1.17: demand / size counts as "need"

	qEnoughRe = regexp.MustCompile(`хват|достаточн|достан|позвол|(может|можно|сможет|получится)[а-я ]{0,30}(купить|оплатить|приобрести|заплатить|взять|позволить)|успе|опозда|сорв|в срок|вовремя|уклад|помест|влез|собрать|in time|on time|meet the deadline|enough|afford|sufficient|short of|short on|(can|could|able)[a-z ]{0,30}(buy|pay|purchase|cover)|\bcover\w*|покрыва|покрыт|\bfit`)
	qShortRe  = regexp.MustCompile(`нехват|не хват|недоста|дефицит|не достаёт|не достает|ещё нужно|еще нужно|short|lack|missing|deficit|how much more`)
	negRe     = regexp.MustCompile(`опозда|сорв|не успе|late|miss the deadline|не хват|недостат|не может|не сможет|нельзя|not enough|insufficient|can'?t|cannot|short of`)

	haveTextRe = regexp.MustCompile(`(?i)((?:^|[.!?]\s+)у\s+[^\d\n.]{1,40}?|на складе|в мешке|в наличии|в запасе|в кармане|в сумке|в копилке|срок через|до дедлайна[^\d\n.]{0,30}осталось|есть|имеется|имеет|осталось|накопил[а-я]*|в кошельке|на счету|на счёте|баланс[а-я]*|бюджет[а-я]*|have|has|had|balance of|budget of)[^\d\n.]{0,15}(\d+(?:[.,]\d+)?)`)
	needTextRe = regexp.MustCompile(`(?i)(стоит|стоят|стоимость[а-я]*|цена[а-я]*|нужно|нужен|нужна|требуется|необходимо|работы ещё на|работы еще на|работы на|costs?|price[sd]?|needs?|requires?)[^\d\n.]{0,15}(\d+(?:[.,]\d+)?)`)

	rngRe        = regexp.MustCompile(`(\d+(?:[.,]\d+)?)\s*(?:-|–|—|до|to)\s*(\d+(?:[.,]\d+)?)`)
	moreRe       = regexp.MustCompile(`(?:больше|более|свыше|от|over|more than|above|at least)\s*(\d+(?:[.,]\d+)?)|(\d+(?:[.,]\d+)?)\s*\+|(\d+(?:[.,]\d+)?)\s*(?:и|or)\s*(?:больше|более|more)`)
	lessRe       = regexp.MustCompile(`(?:меньше|менее|less than|under|below)\s*(\d+(?:[.,]\d+)?)`)
	partWholeQRe = regexp.MustCompile(`(^|[^а-яё])(всю|весь|все|всё|целиком|полностью)([^а-яё]|$)|\b(all|whole|entire|fully)\b`)
	partWholeRe  = regexp.MustCompile(`(?i)(\d+(?:[.,]\d+)?)[^\d\n.]{0,30}?\s(?:из|of|out of)\s+(\d+(?:[.,]\d+)?)`)
	zeroRe       = regexp.MustCompile(`хватает полностью|хватает|достаточно|не нужно|нет нехватки|без нехватки|enough|no shortfall|nothing missing|fully covered`)
)

func qStems(s string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		r := []rune(w)
		if len(r) < 3 {
			continue
		}
		if len(r) > 4 {
			r = r[:4]
		}
		out = append(out, string(r))
	}
	return out
}

func hasStem(key string, list []string) bool {
	for _, k := range qStems(key) {
		for _, s := range list {
			if strings.HasPrefix(k, s) || strings.HasPrefix(s, k) && len(k) >= 4 {
				return true
			}
		}
	}
	return false
}

func num(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(t), ",", "."), 64)
		return f, err == nil
	}
	return 0, false
}

// haveNeed returns available and required amounts (state fields first, then text).
func haveNeed(state any, st, qText string) (have, need float64, ev string, ok bool) {
	var hs, ns []string
	var hv, nv []float64
	for k, v := range fields(state) {
		f, isNum := num(v)
		if !isNum {
			continue
		}
		last := k[strings.LastIndex(k, ".")+1:]
		h, n := hasStem(last, haveStems), hasStem(last, needStems)
		switch {
		case h && !n:
			hs, hv = append(hs, last), append(hv, f)
		case n && !h:
			ns, nv = append(ns, last), append(nv, f)
		}
	}
	if len(hv) == 1 && len(nv) == 1 {
		return hv[0], nv[0], fmt.Sprintf("%s = %g, %s = %g", hs[0], hv[0], ns[0], nv[0]), true
	}
	if len(hv) == 0 && len(nv) == 1 && qText != "" { // v1.17: «у_Нафани_шмурдиков» + «Хватит ли шмурдиков?»
		qs := map[string]bool{}
		for _, w := range qStems(qText) {
			qs[w] = true
		}
		var ok []string
		var ov []float64
		for k, v := range fields(state) {
			f, isNum := num(v)
			last := k[strings.LastIndex(k, ".")+1:]
			if !isNum || last == ns[0] || hasStem(last, needStems) {
				continue
			}
			for _, w := range qStems(last) {
				if qs[w] {
					ok, ov = append(ok, last), append(ov, f)
					break
				}
			}
		}
		if len(ov) == 1 {
			return ov[0], nv[0], fmt.Sprintf("%s = %g, %s = %g", ok[0], ov[0], ns[0], nv[0]), true
		}
	}
	hm, nm := haveTextRe.FindAllStringSubmatch(st, -1), needTextRe.FindAllStringSubmatch(st, -1)
	if len(hm) >= 1 && len(nm) >= 1 {
		h0, _ := num(hm[0][2])
		n0, _ := num(nm[0][2])
		for _, m := range hm[1:] { // all mentions must agree
			if x, _ := num(m[2]); x != h0 {
				return 0, 0, "", false
			}
		}
		for _, m := range nm[1:] {
			if x, _ := num(m[2]); x != n0 {
				return 0, 0, "", false
			}
		}
		return h0, n0, fmt.Sprintf("в тексте: есть %g, нужно %g", h0, n0), true
	}
	return 0, 0, "", false
}

type bucket struct{ lo, hi float64 } // shortfall in (lo, hi]

func optionBucket(o s1.Option) (bucket, bool) {
	t := strings.ToLower(o.Text)
	p := func(s string) float64 { f, _ := num(s); return f }
	if m := rngRe.FindStringSubmatch(t); m != nil {
		return bucket{p(m[1]) - 0.5, p(m[2]) + 0.5}, true
	}
	if m := moreRe.FindStringSubmatch(t); m != nil {
		for _, g := range m[1:] {
			if g != "" {
				lo := p(g)
				if strings.Contains(t, "от ") || strings.Contains(t, "at least") || strings.Contains(t, "+") {
					lo -= 0.5
				} else {
					lo += 0.5
				}
				return bucket{lo, math.Inf(1)}, true
			}
		}
	}
	if m := lessRe.FindStringSubmatch(t); m != nil {
		return bucket{0, p(m[1]) - 0.5}, true
	}
	if zeroRe.MatchString(t) && !strings.Contains(t, "не хват") {
		return bucket{math.Inf(-1), 0}, true
	}
	return bucket{}, false
}

// covBand is a coverage-percent interval [lo, hi): lo inclusive, hi exclusive
// unless hiIncl (an explicit "включительно" on the upper bound).
type covBand struct {
	lo, hi  float64
	hiIncl  bool
}

// coverageQuestion reports whether score options describe coverage percent
// ("less than 25%", "at least 50% but less than 100%") rather than absolute
// shortfall. Such options match have/need ratio, not shortfall buckets.
func coverageQuestion(q s1.ExpertQuestion) bool {
	if q.Type != s1.TypeScore {
		return false
	}
	pct := false
	for _, o := range q.Options {
		t := strings.ToLower(o.Text)
		if strings.Contains(t, "%") || strings.Contains(t, "percent") || strings.Contains(t, "процент") {
			pct = true
			break
		}
	}
	if !pct {
		return false
	}
	qt := strings.ToLower(q.Instr)
	for _, o := range q.Options {
		qt += " " + strings.ToLower(o.Text)
	}
	// Shortfall-percent questions ("by how many percent short?") stay on the
	// shortfall path even with % options.
	if qShortRe.MatchString(qt) {
		return false
	}
	return true
}

var (
	covLowerRe = regexp.MustCompile(`(?:не\s+меньше|not\s+less|at\s+least|от)\s*(\d+(?:[.,]\d+)?)`)
	covUpperRe = regexp.MustCompile(`(?:меньше|менее|less\s+than|under|below|до)\s*(\d+(?:[.,]\d+)?)`)
	covNumRe   = regexp.MustCompile(`(\d+(?:[.,]\d+)?)\s*(?:-|–|—|до|to)\s*(\d+(?:[.,]\d+)?)`)
)

// coverageBand parses one coverage-percent option into [lo, hi): lower bound
// from от/at least/не меньше, upper from до/меньше/less than. A trailing
// "включительно" on the upper bound (without "не") makes it inclusive.
func coverageBand(text string) (covBand, bool) {
	t := strings.ToLower(text)
	p := func(s string) float64 { f, _ := num(s); return f }
	lo, hi, hiIncl, found := 0.0, math.Inf(1), false, false
	if m := covLowerRe.FindStringSubmatch(t); m != nil {
		lo, found = p(m[1]), true
	}
	if m := covUpperRe.FindStringSubmatch(t); m != nil {
		upPos := strings.Index(t, m[0])
		sameAsLower := false
		// "не меньше N" also contains "меньше N" — that hit belongs to the
		// lower bound, not the upper one. Anything else ("от X ... до Y")
		// sets a genuine upper bound.
		if lm := covLowerRe.FindStringSubmatch(t); lm != nil && (strings.Contains(lm[0], "не ") || strings.Contains(lm[0], "not")) {
			sameAsLower = strings.Index(t, lm[0])+len(lm[0])-len(m[0]) == upPos
		}
		if !sameAsLower {
			hi, found = p(m[1]), true
		}
	}
	if m := covNumRe.FindStringSubmatch(t); m != nil && !covLowerRe.MatchString(t) && !covUpperRe.MatchString(t) {
		lo, hi, found = p(m[1]), p(m[2]), true
	}
	if !found {
		return covBand{}, false
	}
	if strings.Contains(t, "включительно") && !strings.Contains(t, "не включительно") {
		// An explicit inclusive marker on the only/other bound applies to hi
		// ("до 50% включительно"); plain от/at-least lowers are inclusive
		// by definition and need no marker.
		if !covUpperRe.MatchString(t) || strings.Index(t, "включительно") > strings.Index(t, "до") {
			hiIncl = true
		}
	}
	return covBand{lo, hi, hiIncl}, true
}

func (Quantity) Answer(state any, stateText string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if q.Task != "" && q.Task != s1.TaskMath {
		return s1.ExpertAnswer{}, false
	}
	if a, ok := typedQuantityAnswer(stateText, q); ok {
		return a, true
	}
	if a, ok := measureAnswer(state, stateText, q); ok {
		return a, true
	}
	instr := strings.ToLower(q.Instr)
	qt := text(q)
	trueText := ""
	for _, o := range q.Options {
		if strings.ToLower(o.Key) == "true" {
			trueText = strings.ToLower(o.Text)
		}
	}
	switch q.Type {
	case s1.TypeScore:
		if !qShortRe.MatchString(qt) || len(q.Options) < 2 {
			return s1.ExpertAnswer{}, false
		}
		have, need, ev, ok := haveNeed(state, stateText, qt)
		if !ok {
			return s1.ExpertAnswer{}, false
		}
		short := need - have
		hit, parsed := -1, 0
		for i, o := range q.Options {
			b, ok := optionBucket(o)
			if !ok {
				continue
			}
			parsed++
			if short > b.lo && short <= b.hi || (math.IsInf(b.lo, -1) && short <= 0) {
				if hit >= 0 {
					return s1.ExpertAnswer{}, false // overlapping ranges: ambiguous
				}
				hit = i
			}
		}
		if hit < 0 || parsed < 2 {
			return s1.ExpertAnswer{}, false
		}
		a := peaked(len(q.Options), hit, 0.9, fmt.Sprintf("%s → не хватает %g", ev, math.Max(0, short)))
		a.Source = "quantity-rule"
		return a, true
	case s1.TypeNoul:
		if !qEnoughRe.MatchString(qt) && qShortRe.MatchString(instr) {
			if have, need, ev, ok := haveNeed(state, stateText, qt); ok {
				p := 0.05
				if have < need {
					p = 0.95
				}
				return s1.ExpertAnswer{Probs: []float64{p}, Evidence: []string{fmt.Sprintf("%s → нехватка %g", ev, math.Max(0, need-have))}, Source: "quantity-rule", Calibrated: true}, true
			}
		}
		if qEnoughRe.MatchString(qt) {
			if have, need, ev, ok := haveNeed(state, stateText, qt); ok {
				enough := have >= need
				neg := negRe.MatchString(instr)
				if !neg && trueText != "" && negRe.MatchString(trueText) && !strings.Contains(instr, "хват") {
					neg = true
				}
				yesP := 0.95
				if enough == neg {
					yesP = 0.05
				}
				verdict := "хватает"
				if !enough {
					verdict = fmt.Sprintf("не хватает %g", need-have)
				}
				return s1.ExpertAnswer{Probs: []float64{yesP}, Evidence: []string{ev + " → " + verdict}, Source: "quantity-rule", Calibrated: true}, true
			}
		}
		// v1.17: «съела 2 порции из 5» + «съела всю норму?»
		if partWholeQRe.MatchString(instr) && !negRe.MatchString(instr) {
			if m := partWholeRe.FindAllStringSubmatch(stateText, -1); len(m) == 1 {
				a, _ := num(m[0][1])
				b, _ := num(m[0][2])
				if b > 0 {
					p := 0.07
					if a >= b {
						p = 0.93
					}
					return s1.ExpertAnswer{Probs: []float64{p}, Evidence: []string{fmt.Sprintf("в тексте: %g из %g", a, b)}, Source: "quantity-rule", Calibrated: true}, true
				}
			}
		}
		// boolean flag spelled out by the question: «хватает_денег»: false ↔ «денег хватает?»
		qs := map[string]bool{}
		for _, s := range qStems(instr + " " + trueText) {
			qs[s] = true
		}
		if negRe.MatchString(instr) {
			return s1.ExpertAnswer{}, false
		}
		var hitKey string
		var hitVal, found bool
		for k, v := range fields(state) {
			b, isBool := v.(bool)
			if !isBool {
				continue
			}
			last := k[strings.LastIndex(k, ".")+1:]
			ks := qStems(last)
			if len(ks) < 2 {
				continue
			}
			all := true
			for _, s := range ks {
				if !qs[s] {
					all = false
					break
				}
			}
			if all {
				if found {
					return s1.ExpertAnswer{}, false
				}
				hitKey, hitVal, found = last, b, true
			}
		}
		if found {
			p := 0.93
			if !hitVal {
				p = 0.07
			}
			return s1.ExpertAnswer{Probs: []float64{p}, Evidence: []string{fmt.Sprintf("поле %s = %v", hitKey, hitVal)}, Source: "quantity-rule", Calibrated: true}, true
		}
	}
	return s1.ExpertAnswer{}, false
}
