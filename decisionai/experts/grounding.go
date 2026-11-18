package experts

import (
	"math"
	"regexp"
	"strings"
	"unicode"

	"decisionai/s1"
)

// Grounding check for "bot answer vs knowledge base" transcripts: a lexical entailment proxy.
// The bot's content words (minus the topic words it echoes from the user's question) must be
// covered by the knowledge-base text; affirming a topic the KB never mentions is a hallucination.

var (
	qGroundRe  = regexp.MustCompile(`backed by|supported by|grounded|based on the (kb|knowledge)|consistent with the (kb|knowledge)|according to the (kb|knowledge)|опира[а-я]*|(подтвержда|основан|соответству|соглас)[а-я ]{0,25}баз[а-я]* знан`)
	qHalluRe   = regexp.MustCompile(`make (something|things|anything) up|made (something|things|anything) up|invent|hallucinat|fabricat|выдум|галлюцин|придума|сочинил`)
	kbLineRe   = regexp.MustCompile(`(?im)^\s*(knowledge base|kb|faq|docs?|база знаний|бз|справка|документация)\s*:\s*(.+)$`)
	botLineRe  = regexp.MustCompile(`(?im)^\s*(bot|assistant|agent|ai|бот|ассистент|агент|оператор)\s*:\s*(.+)$`)
	usrLineRe  = regexp.MustCompile(`(?im)^\s*(user|customer|client|пользователь|клиент)\s*:\s*(.+)$`)
	qBotRateRe = regexp.MustCompile(`(rate|quality|grade|score|correct|accura)[a-z ]{0,20}(bot|assistant|agent)|(bot|assistant|agent)[a-z' ]{0,20}(rate|quality|grade|score|correct|accura)|(оцен|качеств|корректн|правильн)[а-я ]{0,25}(бот|ассистент)|(бот|ассистент)[а-я ]{0,25}(оцен|качеств|корректн|правильн)`)
	affirmRe   = regexp.MustCompile(`(?i)^\W*(yes|yeah|yep|sure|of course|absolutely|certainly|да|конечно|разумеется|безусловно)\b`)
)

var groundStop = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`yes yeah yep sure course absolutely certainly just also and the you your our can will would
		with for that this have has are was were not but any all its it's just please pick choose usually typically normally
		да конечно разумеется безусловно обычно как правило просто также это этот эта для вас ваш ваша наш наша можно будет есть
		или если при так уже ещё еще его она они вам нам там тут здесь`) {
		groundStop[w] = true
	}
}

func groundTokens(s string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		r := []rune(w)
		if groundStop[w] || (len(r) < 3 && !unicode.IsDigit(r[0])) {
			continue
		}
		if len(r) > 5 {
			r = r[:5]
		}
		out = append(out, string(r))
	}
	return out
}

// grounded returns (support ratio, affirmed-missing-topic, ok).
func grounded(st string) (float64, string, bool) {
	kb, bot, usr := kbLineRe.FindAllStringSubmatch(st, -1), botLineRe.FindAllStringSubmatch(st, -1), usrLineRe.FindAllStringSubmatch(st, -1)
	if len(kb) == 0 || len(bot) == 0 {
		return 0, "", false
	}
	kbSet, qSet := map[string]bool{}, map[string]bool{}
	for _, m := range kb {
		for _, t := range groundTokens(m[2]) {
			kbSet[t] = true
		}
	}
	for _, m := range usr {
		for _, t := range groundTokens(m[2]) {
			qSet[t] = true
		}
	}
	reply := bot[len(bot)-1][2]
	n, hit, missing := 0, 0, ""
	for _, t := range groundTokens(reply) {
		if kbSet[t] {
			n++
			hit++
			continue
		}
		if qSet[t] {
			if missing == "" {
				missing = t
			}
			continue
		}
		n++
	}
	if n == 0 {
		return 0, "", false
	}
	if !affirmRe.MatchString(reply) {
		missing = ""
	}
	return float64(hit) / float64(n), missing, true
}

func groundAnswer(st string, q s1.ExpertQuestion, qt string) (s1.ExpertAnswer, bool) {
	isG, isH := qGroundRe.MatchString(qt), qHalluRe.MatchString(qt)
	if q.Type == s1.TypeScore && len(q.Options) >= 2 && qBotRateRe.MatchString(qt) {
		sup, miss, ok := grounded(st)
		if !ok {
			return s1.ExpertAnswer{}, false
		}
		lv := optionLevels(q.Options)
		target, ev := -1.0, ""
		switch {
		case sup <= 0.3 || (miss != "" && sup < 0.7):
			target, ev = 0, "ответ бота не подтверждается базой знаний"
		case sup >= 0.7:
			target, ev = 1, "ответ бота покрыт базой знаний"
		default:
			return s1.ExpertAnswer{}, false
		}
		bi := 0
		for i, l := range lv {
			if math.Abs(l-target) < math.Abs(lv[bi]-target) {
				bi = i
			}
		}
		return peaked(len(q.Options), bi, 0.8, ev), true
	}
	if q.Type != s1.TypeNoul || (!isG && !isH) {
		return s1.ExpertAnswer{}, false
	}
	sup, miss, ok := grounded(st)
	if !ok {
		return s1.ExpertAnswer{}, false
	}
	var pg float64
	var ev string
	switch {
	case sup <= 0.3 || (miss != "" && sup < 0.7):
		pg, ev = 0.12, "в ответе бота есть утверждения, которых нет в базе знаний"
		if miss != "" {
			ev = "бот подтверждает «" + miss + "…», но в базе знаний этого нет"
		}
	case sup >= 0.7:
		pg, ev = 0.86, "слова ответа бота покрыты базой знаний"
	default:
		return s1.ExpertAnswer{}, false
	}
	if isH && !isG {
		pg = 1 - pg
	}
	return yes(pg, ev), true
}
