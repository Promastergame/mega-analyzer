package s1

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// Lexical evidence fusion.
//
// The bi-encoder is good at "which text is closer in meaning" but weak at domain cues: it can rank
// "crypto" above "secrets" for a hardcoded sk_live key. Fusion adds a second, transparent signal:
//
//  1. Concept lexicon. Every option (key + description) and every noul instruction is linked to known
//     concepts (secrets, billing, shipping, anger, human request ...). The state is scanned for each
//     concept's trigger phrases, with negation handling ("сетевых запросов не было", "no network").
//  2. Description overlap. Content words of the option description found in the state, so custom
//     categories without a lexicon entry still get a lexical vote.
//
// The result is added to the neural logits; matched phrases become evidence. Routing rules do not change:
// fused answers still go through the general model's calibration and are capped at "review" without it.

type concept struct {
	name     string
	aliases  []string // stems that link an option/instruction to the concept
	triggers []string // phrases searched in the state; "=x" means exact token, otherwise prefix
}

var concepts = []concept{
	{"secrets", []string{"secret", "credential", "password", "token", "apikey", "секрет", "ключ", "токен", "парол", "утечк", "leak", "учётн", "учетн"},
		[]string{"api key", "apikey", "api_key", "secret", "token", "password", "passwd", "credential", "private key", "bearer", "authorization", "hardcoded", "hard-coded", "секрет", "ключ", "токен", "парол", "захардкож", "зашит"}},
	{"crypto", []string{"crypt", "cipher", "hash", "крипт", "шифр", "хэш", "хеш"},
		[]string{"=md5", "=sha1", "=sha-1", "=des", "=3des", "=ecb", "=rc4", "aes/ecb", "cipher", "messagedigest", "=iv", "static iv", "weak hash", "encrypt", "decrypt", "шифр", "крипт", "хэш", "хеш"}},
	{"network", []string{"network", "http", "=tls", "=ssl", "transport", "сет", "трафик"},
		[]string{"=http", "cleartext", "=ssl", "=tls", "trustmanager", "hostnameverifier", "certificate", "pinning", "allowallhostname", "usescleartexttraffic", "сертификат", "незащищ", "трафик"}},
	{"storage", []string{"storage", "stored", "store", "хранен", "хранил", "файл", "диск"},
		[]string{"sharedpreferences", "external storage", "getexternal", "sqlite", "database", "sdcard", "mode_world", "openfileoutput", "хранен", "файл", "базе данных"}},
	{"returns", []string{"return", "exchang", "возврат", "обмен", "поврежд", "damag"},
		[]string{"wrong size", "wrong item", "wrong colo", "damaged", "broken", "defect", "exchange", "return it", "send it back", "doesn't fit", "does not fit", "too small", "too big", "не тот", "не подош", "размер", "брак", "поврежд", "обмен", "вернуть товар", "возврат товар"}},
	{"shipping", []string{"ship", "deliver", "доставк", "отправк", "посылк", "курьер"},
		[]string{"late", "delay", "arrived", "arrive", "tracking", "lost package", "never came", "not arrived", "where is my", "deliver", "courier", "shipping", "shipment", "опозд", "задерж", "доставк", "курьер", "трек", "не приш", "не дош", "посылк", "пришл"}},
	{"billing", []string{"bill", "charg", "invoice", "payment", "pay", "оплат", "счёт", "счет", "списан", "платеж", "платёж"},
		[]string{"charge", "charged", "two charges", "double charge", "twice", "=card", "invoice", "payment", "=paid", "refund", "$", "списал", "списан", "дважды", "карт", "оплат", "счёт", "деньг", "возврат денег"}},
	{"angry", []string{"angry", "anger", "furious", "rage", "зл", "гнев", "ярост", "агресс"},
		[]string{"unacceptable", "ridiculous", "furious", "worst", "terrible", "awful", "scam", "disgusting", "!!!", "what are you going to do", "how dare", "lawyer", "безобраз", "ужас", "возмут", "обман", "кошмар", "позор", "в суд"}},
	{"frustrated", []string{"frustrat", "annoy", "upset", "disappoint", "раздраж", "недовол", "расстро"},
		[]string{"again", "still", "late", "wrong", "two weeks", "disappoint", "annoy", "what are you going to do", "also", "опять", "снова", "до сих пор", "недовол", "расстро", "сколько можно"}},
	{"calm", []string{"calm", "neutral", "polite", "спокой", "нейтрал", "вежлив"},
		[]string{"please", "thank", "could you", "would you", "kindly", "пожалуйста", "спасибо", "подскажите", "будьте добры"}},
	{"human", []string{"human", "agent", "person", "operator", "manager", "человек", "оператор", "менеджер", "сотрудник", "живой"},
		[]string{"real person", "human", "operator", "manager", "speak to", "talk to", "call me", "supervisor", "оператор", "менеджер", "живой человек", "позовите", "соедините", "перезвон"}},
	{"urgent", []string{"urgent", "asap", "priority", "срочн", "приоритет"},
		[]string{"urgent", "asap", "immediately", "right now", "today", "срочно", "немедленно", "сегодня", "прямо сейчас"}},
	{"refund", []string{"refund", "money back", "вернуть деньги", "возврат денег", "компенсац"},
		[]string{"refund", "money back", "reimburse", "вернуть деньги", "верните деньги", "возврат денег", "компенсац"}},
}

var negWords = map[string]bool{"не": true, "нет": true, "ни": true, "без": true, "not": true, "no": true, "never": true, "without": true, "none": true, "zero": true, "0": true, "false": true}

type lexDoc struct {
	toks []string
	raw  string
}

func lexDocOf(s string) lexDoc {
	low := strings.ToLower(s)
	toks := strings.FieldsFunc(low, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '$' && r != '/' && r != '-' && r != '\''
	})
	for i, t := range toks {
		toks[i] = strings.Trim(t, "/-'")
	}
	return lexDoc{toks: toks, raw: low}
}

func tokMatch(tok, pat string) bool {
	if strings.HasPrefix(pat, "=") {
		return tok == pat[1:]
	}
	return strings.HasPrefix(tok, pat)
}

// hits returns how many non-negated occurrences of phrase are in the doc, and one example.
func (d lexDoc) hits(phrase string) (int, string) {
	if phrase == "!!!" || phrase == "$" {
		if n := strings.Count(d.raw, phrase); n > 0 {
			return n, phrase
		}
		return 0, ""
	}
	pt := lexDocOf(strings.TrimPrefix(phrase, "=")).toks
	exact := strings.HasPrefix(phrase, "=")
	if len(pt) == 0 {
		return 0, ""
	}
	n, ex := 0, ""
	for i := 0; i+len(pt) <= len(d.toks); i++ {
		ok := true
		for k, p := range pt {
			if exact {
				p = "=" + p
			}
			if !tokMatch(d.toks[i+k], p) {
				ok = false
				break
			}
		}
		if !ok || d.negated(i, i+len(pt)) {
			continue
		}
		n++
		if ex == "" {
			ex = strings.Join(d.toks[i:i+len(pt)], " ")
		}
	}
	return n, ex
}

// negated: "no network", "без сети", "запросов не было", "network_requests: 0".
func (d lexDoc) negated(from, to int) bool {
	for j := max(0, from-2); j < from; j++ {
		if negWords[d.toks[j]] {
			return true
		}
	}
	for j := to; j < min(len(d.toks), to+2); j++ {
		if t := d.toks[j]; t == "не" || t == "нет" || t == "0" || t == "false" || t == "none" {
			return true
		}
	}
	return false
}

// linked returns the concepts whose aliases occur in text (option key + description or instruction).
func linked(text string) []int {
	d := lexDocOf(strings.NewReplacer("_", " ").Replace(text))
	var out []int
	for ci, c := range concepts {
		for _, a := range c.aliases {
			found := false
			for _, t := range d.toks {
				if tokMatch(t, a) || (len([]rune(a)) > 4 && strings.Contains(t, a)) {
					found = true
					break
				}
			}
			if found {
				out = append(out, ci)
				break
			}
		}
	}
	return out
}

var stop = map[string]bool{}

func init() {
	for _, w := range strings.Fields("the a an and or of to in on for with is are was be by at it this that from as not no yes any all your you our we they их это что как для или и в во на по с со к ко из у о об от до за не нет да ли бы же то так где кто при над под без item items problem problems issue issues other прочее другое") {
		stop[w] = true
	}
}

// overlap: share of the description's content stems present in the state.
func overlap(desc string, state lexDoc) (float64, []string) {
	d := lexDocOf(desc)
	set := map[string]bool{}
	for _, t := range state.toks {
		r := []rune(t)
		if len(r) > 5 {
			t = string(r[:5])
		}
		set[t] = true
	}
	seen := map[string]bool{}
	n, hit := 0, 0
	var words []string
	for _, t := range d.toks {
		if stop[t] || len([]rune(t)) < 3 {
			continue
		}
		s := t
		if r := []rune(t); len(r) > 5 {
			s = string(r[:5])
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		n++
		if set[s] {
			hit++
			words = append(words, t)
		}
	}
	if n == 0 {
		return 0, nil
	}
	return float64(hit) / float64(n), words
}

type lexVote struct {
	z     float64  // log-evidence added to the option's logit
	found []string // matched phrases, for evidence
	known bool     // option is linked to at least one concept
}

func conceptVote(ci int, state lexDoc) (float64, []string) {
	total, distinct := 0, 0
	var ex []string
	for _, t := range concepts[ci].triggers {
		if n, e := state.hits(t); n > 0 {
			total += n
			distinct++
			if len(ex) < 3 {
				ex = append(ex, e)
			}
		}
	}
	if total == 0 {
		return 0, nil
	}
	return math.Log1p(float64(distinct)) + 0.25*math.Log1p(float64(total-distinct)), ex
}

// timeMaskOf collects time anchors (past/present/future bitmask) from text,
// using the same stems as the verdict clause analysis in embed.go.
func timeMaskOf(s string) int {
	mask := 0
	for _, t := range lexDocOf(s).toks {
		if bit, ok := timeTable[stem5(t)]; ok {
			mask |= bit
		}
	}
	return mask
}

// optionVotes scores each option of a choice/score question (escape options get 0).
func optionVotes(q compiled, state lexDoc) []lexVote {
	out := make([]lexVote, len(q.Options))
	stateMask := timeMaskOf(state.raw)
	for i, o := range q.Options {
		if isEscape(o) {
			continue
		}
		v := lexVote{}
		for _, ci := range linked(o.Key + " " + o.Text) {
			v.known = true
			z, ex := conceptVote(ci, state)
			v.z += z
			for _, e := range ex {
				v.found = append(v.found, "«"+e+"»")
			}
		}
		if o.Text != "" {
			ov, words := overlap(o.Text, state)
			v.z += 1.2 * ov
			if ov > 0 && len(v.found) == 0 {
				for _, w := range words {
					if len(v.found) < 3 {
						v.found = append(v.found, "«"+w+"»")
					}
				}
			}
		}
		// Lexical overlap across mismatched times is not evidence: the neural
		// verdicts refute such pairs via time markers, but raw shared words
		// ("открыт", "сегодня" on both sides) would re-confirm the option and
		// crush the escape hatch. Zero the vote only on a strict mismatch
		// (both sides carry time words, disjoint); pairs without time words
		// on either side are untouched.
		if hm := timeMaskOf(o.Key + " " + o.Text); stateMask != 0 && hm != 0 && stateMask&hm == 0 {
			v.z = 0
			v.found = nil
		}
		out[i] = v
	}
	return out
}

// noulVote: signed evidence for a yes/no question, from the instruction's (and criteria's) concepts.
// ok=false when the question is not linked to any concept.
func noulVote(q compiled, state lexDoc) (float64, []string, bool) {
	text := q.Instr
	idx := linked(text)
	if len(idx) == 0 {
		return 0, nil, false
	}
	z := 0.0
	var found []string
	for _, ci := range idx {
		v, ex := conceptVote(ci, state)
		if v == 0 {
			z -= 0.6 // the instruction asks about something the state never mentions
			continue
		}
		z += v
		for _, e := range ex {
			found = append(found, "«"+e+"»")
		}
	}
	return z / float64(len(idx)), found, true
}

// LexWeight scales lexical evidence against neural logits. 0 disables fusion.
const LexWeight = 1.6

func lexEvidence(id string, found []string) string {
	sort.Strings(found)
	return "словарь " + id + ": " + strings.Join(dedup(found), ", ")
}

func dedup(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
