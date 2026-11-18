package experts

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"decisionai/s1"
)

// quantityFact keeps units and provenance until the operation has been checked.
// Values are normalized to g, ml, mm, seconds, or one specific currency/count.
type quantityFact struct {
	value, scale                                   float64
	dimension, unit, object, owner, role, evidence string
}

type unitDef struct {
	dimension string
	scale     float64
}

var quantityUnits = map[string]unitDef{
	"кг": {"mass", 1000}, "kg": {"mass", 1000}, "килограмм": {"mass", 1000},
	"г": {"mass", 1}, "g": {"mass", 1}, "грамм": {"mass", 1},
	"мг": {"mass", .001}, "mg": {"mass", .001}, "миллиграмм": {"mass", .001},
	"т": {"mass", 1000000}, "тонн": {"mass", 1000000},
	"л": {"volume", 1000}, "l": {"volume", 1000}, "литр": {"volume", 1000}, "liter": {"volume", 1000}, "litre": {"volume", 1000},
	"мл": {"volume", 1}, "ml": {"volume", 1}, "миллилитр": {"volume", 1},
	"мм": {"length", 1}, "mm": {"length", 1}, "миллиметр": {"length", 1},
	"см": {"length", 10}, "cm": {"length", 10}, "сантиметр": {"length", 10},
	"м": {"length", 1000}, "m": {"length", 1000}, "метр": {"length", 1000},
	"км": {"length", 1000000}, "km": {"length", 1000000}, "километр": {"length", 1000000},
	"с": {"time", 1}, "s": {"time", 1}, "сек": {"time", 1}, "секунд": {"time", 1}, "second": {"time", 1},
	"мин": {"time", 60}, "минут": {"time", 60}, "min": {"time", 60}, "minute": {"time", 60},
	"ч": {"time", 3600}, "час": {"time", 3600}, "h": {"time", 3600}, "hour": {"time", 3600},
	"дн": {"time", 86400}, "день": {"time", 86400}, "дней": {"time", 86400}, "дня": {"time", 86400}, "day": {"time", 86400},
	"руб": {"RUB", 1}, "рубл": {"RUB", 1}, "рублей": {"RUB", 1}, "₽": {"RUB", 1}, "rub": {"RUB", 1},
	"доллар": {"USD", 1}, "usd": {"USD", 1}, "$": {"USD", 1}, "dollar": {"USD", 1},
	"евро": {"EUR", 1}, "eur": {"EUR", 1}, "€": {"EUR", 1},
	"%": {"percent", 1}, "процент": {"percent", 1}, "percent": {"percent", 1},
}

var (
	quantityNumberRe       = regexp.MustCompile(`[-+]?\d+(?:[ \x{00a0}\x{202f}]\d{3})*(?:[.,]\d+)?`)
	quantityWordRe         = regexp.MustCompile(`^[\s:]*([\p{L}%₽$€]+)`)
	quantityHaveRe         = regexp.MustCompile(`(?i)(в наличии|в запасе|на складе|есть|имеет|имеется|осталось|накопил[а-яё]*|бюджет[а-яё]*|баланс[а-яё]*|в кошельке|на счет[уеё]|было|был[аи]|initially|available|stock|budget|balance|\bhas\b|\bhave\b|\bhad\b|канистр[а-яё]*|резервуар[а-яё]*|бак[а-яё]*|цистерн[а-яё]*|бочк[а-яё]*|contains?|holds?|there\s+are|there\s+is|tray|reel)`)
	quantityNeedRe         = regexp.MustCompile(`(?i)(нуж[а-яё]*|требуется|необходимо|надо|цена[а-яё]*|стоимость[а-яё]*|стоит|стоят|needs?|requires?|costs?|price)`)
	quantityAddRe          = regexp.MustCompile(`(?i)(добавил[а-яё]*|долил[а-яё]*|пополнил[а-яё]*|поступило|поступили|положил[а-яё]*|вернул[а-яё]*|added|received|deposited|returned)`)
	quantitySubtractRe     = regexp.MustCompile(`(?i)(слил[а-яё]*|потратил[а-яё]*|израсходовал[а-яё]*|забрал[а-яё]*|убрал[а-яё]*|вылил[а-яё]*|съел[а-яё]*|использовал[а-яё]*|spent|removed|used|drained|consumed)`)
	quantityExtraRe        = regexp.MustCompile(`(?i)(доставк[а-яё]*|комисси[а-яё]*|налог[а-яё]*|shipping|delivery|fee|tax)`)
	quantityDiscountRe     = regexp.MustCompile(`(?i)(скидк[а-яё]*|discount)`)
	quantityOwnerRe        = regexp.MustCompile(`(?i)(?:^|\s)у\s+([\p{L}-]+)`)
	quantityEnglishOwnerRe = regexp.MustCompile(`(?i)([\p{L}-]+)\s+(?:has|had|owns)\s*$`)
	quantityPackRe         = regexp.MustCompile(`(?i)(короб|упаков|пач|пакет|ящик|мешк|box|pack|bag|carton|tray|reel|рулон|моток|катушк|бутылк|bottl|банок|jar|crate)`)
	quantityEachRe         = regexp.MustCompile(`(?i)(?:\sпо\s*|\bof\s*|\bwith\s*|\bholding\s*|\bcontaining\s*)$`)
	quantityUncertainRe    = regexp.MustCompile(`(?i)примерно|около|возможно|неизвест|не указан|optional|approximately|unknown|необязательн`)
)

func quantityUnit(word string) (unitDef, bool) {
	w := strings.ToLower(strings.Trim(word, ".,"))
	if u, ok := quantityUnits[w]; ok {
		return u, true
	}
	// Only inflections of known long unit names, never arbitrary prefixes.
	for _, suffix := range []string{"ами", "ов", "ей", "ам", "ах", "ом", "а", "я", "ы", "и", "у", "ь", "s"} {
		if root := strings.TrimSuffix(w, suffix); root != w && len([]rune(root)) >= 3 {
			if u, ok := quantityUnits[root]; ok {
				return u, true
			}
		}
	}
	return unitDef{}, false
}

func quantityRole(prefix string) string {
	if quantityNeedRe.MatchString(prefix) && (strings.Contains(strings.ToLower(prefix), "до скидк") || strings.Contains(strings.ToLower(prefix), "before discount")) {
		return "need"
	}
	// An extra cost or discount named as the subject ("доставка стоит 150",
	// "shipping costs 13") keeps its role even when a need-verb follows —
	// otherwise the expense is misread as a separate need and totals break.
	tail := prefix
	if rs := []rune(prefix); len(rs) > 30 {
		tail = string(rs[len(rs)-30:])
	}
	if quantityExtraRe.MatchString(tail) {
		return "extra"
	}
	if quantityDiscountRe.MatchString(tail) {
		return "discount"
	}
	best, role := -1, ""
	for _, rule := range []struct {
		re   *regexp.Regexp
		role string
	}{
		{quantityHaveRe, "have"}, {quantityNeedRe, "need"}, {quantityAddRe, "add"},
		{quantitySubtractRe, "subtract"}, {quantityExtraRe, "extra"}, {quantityDiscountRe, "discount"},
	} {
		for _, m := range rule.re.FindAllStringIndex(prefix, -1) {
			if m[0] >= best {
				best, role = m[0], rule.role
			}
		}
	}
	if role == "" && quantityOwnerRe.MatchString(prefix) {
		return "have"
	}
	return role
}

func quantityOwnerKey(s string) string {
	s = strings.ToLower(s)
	rs := []rune(s)
	if len(rs) > 3 && strings.ContainsRune("аяеуыию", rs[len(rs)-1]) {
		s = string(rs[:len(rs)-1])
	}
	return s
}

func quantityKey(text string) string {
	words := qStems(text)
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

func quantityFacts(text string) ([]quantityFact, bool) {
	indices := quantityNumberRe.FindAllStringIndex(text, -1)
	var facts []quantityFact
	complex := false
	for i, at := range indices {
		start := 0
		if i > 0 {
			start = indices[i-1][1]
		}
		prefix := text[start:at[0]]
		// A role belongs to its clause, not an earlier sentence's subject.
		if cut := strings.LastIndexAny(prefix, ".;\n"); cut >= 0 {
			prefix = prefix[cut+1:]
		}
		end := len(text)
		if i+1 < len(indices) {
			end = indices[i+1][0]
		}
		tail := text[at[1]:end]
		role := quantityRole(prefix)
		packed := len(facts) > 0 && quantityEachRe.MatchString(prefix) && quantityPackRe.MatchString(facts[len(facts)-1].unit)
		if packed {
			role, complex = facts[len(facts)-1].role, true
		}
		if role == "" {
			continue
		}
		raw := strings.NewReplacer(" ", "", "\u00a0", "", "\u202f", "", ",", ".").Replace(text[at[0]:at[1]])
		value, ok := num(raw)
		if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return nil, true
		}
		fact := quantityFact{value: value, scale: 1, role: role, evidence: strings.TrimSpace(prefix + text[at[0]:at[1]])}
		if m := quantityWordRe.FindStringSubmatch(tail); m != nil {
			fact.unit = strings.ToLower(m[1])
			// Packs ("6 sealed boxes"): the container noun may follow an
			// adjective — look one word ahead for a pack word so the pack
			// multiplier below sees boxes, not "sealed".
			rest := tail[len(m[0]):]
			if mm := quantityWordRe.FindStringSubmatch(rest); mm != nil {
				if w := strings.ToLower(mm[1]); quantityPackRe.MatchString(w) {
					fact.unit = w
				}
			}
			if u, known := quantityUnit(fact.unit); known {
				fact.dimension, fact.scale = u.dimension, u.scale
				fact.value *= u.scale
				if obj := quantityWordRe.FindStringSubmatch(tail[len(m[0]):]); obj != nil {
					fact.object = quantityKey(obj[1])
				}
			} else {
				fact.dimension, fact.object = "count:"+quantityKey(fact.unit), quantityKey(fact.unit)
			}
			fact.evidence += " " + fact.unit
		}
		if fact.unit == "" {
			trimmed := strings.TrimSpace(prefix)
			for _, symbol := range []string{"$", "€", "₽"} {
				if strings.HasSuffix(trimmed, symbol) {
					u, _ := quantityUnit(symbol)
					fact.unit, fact.dimension = symbol, u.dimension
				}
			}
		}
		if m := quantityOwnerRe.FindStringSubmatch(prefix); m != nil {
			fact.owner = quantityOwnerKey(m[1])
		}
		if m := quantityEnglishOwnerRe.FindStringSubmatch(prefix); m != nil {
			fact.owner = quantityOwnerKey(m[1])
		}
		if packed {
			prior := facts[len(facts)-1]
			fact.value *= prior.value
			fact.owner = prior.owner
			fact.evidence = fmt.Sprintf("%s × %g %s = %g", prior.evidence, value, fact.unit, fact.value/fact.scale)
			facts[len(facts)-1] = fact
			continue
		}
		if role == "extra" || role == "discount" || role == "add" || role == "subtract" {
			complex = true
		}
		facts = append(facts, fact)
	}
	return facts, complex
}

func quantityCompatible(a, b quantityFact) bool {
	if a.dimension != b.dimension {
		return false
	}
	// Currency and physical dimensions are not substitutes for object identity:
	// 2 kg sugar cannot satisfy a request for 1 kg flour.
	if a.dimension == "mass" || a.dimension == "volume" || a.dimension == "length" {
		return a.object == "" || b.object == "" || a.object == b.object
	}
	return true
}

func typedQuantityAnswer(stateText string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if (q.Task != "" && q.Task != s1.TaskMath) || (q.Type != s1.TypeNoul && q.Type != s1.TypeScore) {
		return s1.ExpertAnswer{}, false
	}
	instr := strings.ToLower(q.Instr)
	if !qEnoughRe.MatchString(instr) && !qShortRe.MatchString(instr) && !coverageQuestion(q) {
		return s1.ExpertAnswer{}, false
	}
	facts, complex := quantityFacts(stateText)
	var have, need, changes, extras, discounts []quantityFact
	for _, fact := range facts {
		switch fact.role {
		case "have":
			have = append(have, fact)
		case "need":
			need = append(need, fact)
		case "add", "subtract":
			changes = append(changes, fact)
		case "extra":
			extras = append(extras, fact)
		case "discount":
			discounts = append(discounts, fact)
		}
	}
	if len(have) == 0 || len(need) == 0 {
		return s1.ExpertAnswer{}, false
	}
	if len(have) > 1 {
		var selected []quantityFact
		for _, h := range have {
			if h.owner == "" {
				continue
			}
			for _, word := range strings.FieldsFunc(instr, func(r rune) bool { return !((r >= 'а' && r <= 'я') || r == 'ё' || (r >= 'a' && r <= 'z')) }) {
				if quantityOwnerKey(word) == h.owner {
					selected = append(selected, h)
					break
				}
			}
		}
		if len(selected) == 1 {
			have = selected
		}
	}
	refuse := func(reason string) (s1.ExpertAnswer, bool) {
		a := uncertain(q, "quantity_ambiguous", reason)
		a.Source = "quantity-rule"
		return a, true
	}
	if len(have) != 1 || len(need) != 1 {
		return refuse("Не удалось однозначно связать запас и потребность с одним объектом и владельцем.")
	}
	h, n := have[0], need[0]
	if h.dimension == "" && n.dimension == "" && !complex {
		return s1.ExpertAnswer{}, false
	}
	if !quantityCompatible(h, n) || h.dimension == "" || n.dimension == "" {
		return refuse("Единицы или объекты запаса и потребности различаются либо не указаны; сравнение не подтверждено.")
	}
	if quantityUncertainRe.MatchString(stateText) {
		return refuse("В числовых условиях есть неопределённость или необязательные расходы.")
	}
	evidence := []string{h.evidence, n.evidence}
	available, required := h.value, n.value
	trace := &s1.CalculationTrace{InitialAvailable: h.value, InitialRequired: n.value, Unit: h.dimension}
	for _, fact := range facts {
		trace.Facts = append(trace.Facts, s1.CalculationFact{Value: fact.value, Role: fact.role, Source: fact.evidence})
	}
	for _, change := range changes {
		if !quantityCompatible(h, change) || (change.owner != "" && h.owner != "" && change.owner != h.owner) {
			return refuse("Не удалось привязать изменение количества к исходному запасу.")
		}
		if change.role == "subtract" {
			available -= change.value
		} else {
			available += change.value
		}
		op := "add"
		if change.role == "subtract" {
			op = "subtract"
		}
		trace.Steps = append(trace.Steps, s1.CalculationStep{Target: "available", Operation: op, Operand: change.value, Result: available})
		evidence = append(evidence, change.evidence)
	}
	if available < 0 {
		return refuse("Последовательность изменений даёт отрицательный физический запас.")
	}
	if len(discounts) > 1 {
		return refuse("Порядок применения нескольких скидок не задан.")
	}
	for _, discount := range discounts {
		if discount.dimension != "percent" || discount.value > 100 || (n.dimension != "RUB" && n.dimension != "USD" && n.dimension != "EUR") {
			return refuse("Не удалось определить базу и единицы скидки.")
		}
		required *= 1 - discount.value/100
		trace.Steps = append(trace.Steps, s1.CalculationStep{Target: "required", Operation: "discount_percent", Operand: discount.value, Result: required})
		evidence = append(evidence, discount.evidence)
	}
	for _, extra := range extras {
		if !quantityCompatible(n, extra) {
			return refuse("Дополнительные расходы заданы в несовместимых единицах.")
		}
		required += extra.value
		trace.Steps = append(trace.Steps, s1.CalculationStep{Target: "required", Operation: "add", Operand: extra.value, Result: required})
		evidence = append(evidence, extra.evidence)
	}
	enough := available > required || feq(available, required)
	shortfall := math.Max(0, (required-available)/n.scale)
	trace.Available, trace.Required, trace.Shortfall, trace.Enough = available, required, math.Max(0, required-available), enough
	trace.Verified = trace.Verify()
	if !trace.Verified {
		return refuse("Не пройдена арифметическая проверка вычислений.")
	}
	evidence = append(evidence, fmt.Sprintf("После приведения единиц и всех операций: %g %s доступно, %g %s требуется; нехватка %g %s.", available/n.scale, n.unit, required/n.scale, n.unit, shortfall, n.unit))
	if q.Type == s1.TypeNoul {
		negative := negRe.MatchString(instr) || (!qEnoughRe.MatchString(instr) && qShortRe.MatchString(instr))
		for _, option := range q.Options {
			if option.Key == "true" && !strings.Contains(instr, "хват") && negRe.MatchString(strings.ToLower(option.Text)) {
				negative = true
			}
		}
		if q.Polarity == "negative" {
			negative = true
		}
		p := .97
		if enough == negative {
			p = .03
		}
		return s1.ExpertAnswer{Probs: []float64{p}, Evidence: evidence, Source: "quantity-rule", Calibrated: true, Calculation: trace}, true
	}
	hit := -1
	covQ := coverageQuestion(q)
	for i, option := range q.Options {
		if covQ {
			band, ok := coverageBand(option.Text)
			if !ok {
				continue
			}
			if required <= 0 {
				return s1.ExpertAnswer{}, false
			}
			cov := 100 * available / required
			if cov >= band.lo && (cov < band.hi || (cov == band.hi && band.hiIncl)) {
				if hit >= 0 {
					return refuse("Диапазоны вариантов ответа пересекаются.")
				}
				hit = i
			}
			continue
		}
		bucket, ok := optionBucket(option)
		if !ok {
			continue
		}
		if shortfall > bucket.lo && shortfall <= bucket.hi {
			if hit >= 0 {
				return refuse("Диапазоны вариантов ответа пересекаются.")
			}
			hit = i
		}
	}
	if hit < 0 {
		return s1.ExpertAnswer{}, false
	}
	a := peaked(len(q.Options), hit, .95, strings.Join(evidence, "; "))
	a.Source = "quantity-rule"
	a.Calculation = trace
	return a, true
}
