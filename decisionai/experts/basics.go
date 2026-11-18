package experts

// Basics: deterministic detectors for "base" text tasks where a small bi-encoder is weak and a
// rule is exact: payment-card numbers, personal data, prompt injection, language identification,
// spam / scam signals. Each detector answers only when its question is recognised AND (for most)
// only when it found positive evidence; otherwise the question falls through to the general model.

import (
	"regexp"
	"strings"
	"unicode"

	"decisionai/s1"
)

type Basics struct{}

func (Basics) Name() string { return "basics-rule" }

var (
	qCardRe   = regexp.MustCompile(`card number|payment card|credit card|debit card|номер[а-я ]*карт|банковск[а-я]* карт|карт[а-я]* номер|pan\b`)
	qPIIRe    = regexp.MustCompile(`personal data|personal information|personally identifiable|\bpii\b|redact|sensitive data|персональн|личн[а-я]* данн|конфиденциальн[а-я]* данн|нужно скрыть|замаскир|контакт[а-я]* (данн|информац)?[а-я ]*нельзя|нельзя публиковать|contact (details|info)|doxx`)
	qInjRe    = regexp.MustCompile(`prompt injection|inject|hijack|jailbreak|override (its|the) instructions|перехват|инъекц|джейлбрейк|подмен[а-я]* инструкц|hidden (command|instruction|prompt)|(command|instruction)s? (aimed at|for|to) the (ai|agent|assistant|model|llm)|скрыт[а-я]* (команд|инструкц)|(команд|инструкц)[а-я]* для (ии|ai|агента|ассистента|модели|бота)`)
	qFollowRe = regexp.MustCompile(`should (the )?(agent|assistant|ai|bot|model|llm) (follow|obey|execute|comply|do what)|(следовать|подчиниться|выполн(ить|ять)) [а-я ]{0,20}(инструкц|команд|текст|указан)|(агент|ассистент|бот|модель|ии)[а-я]* (следовать|выполнить|подчиниться)`)
	qPhishRe  = regexp.MustCompile(`phish|social engineering|scam|fraud|impersonat|фишинг|социальн[а-я]* инженер|мошенн|развод`)
	qFulfilRe = regexp.MustCompile(`(should|can|may) (we|i|you|the team)? ?(fulfil|fulfill|comply|send it|do (it|this|as asked))|request be (fulfil|fulfill|granted|done)|выполнить (эту |его |её )?(просьбу|запрос)|стоит ли (выполн|отправ|переда)`)
	qSpamRe   = regexp.MustCompile(`\bspam|реклам|спам|promotional|advertis|unsolicited`)
	qReplyRe  = regexp.MustCompile(`(requires?|needs?|need|deserve)s? (a )?(reply|response|answer)|should (we|i) (reply|respond|answer)|(требуется|нужен|нужно|нужно ли|стоит ли) (ли )?(ответ|отвеч)`)
	qToxRe    = regexp.MustCompile(`toxic|hate|offensive|insult|abusive|harass|slur|оскорб|токсичн|ненавист|травл|угроз`)
	toxRe     = regexp.MustCompile(`(?i)shouldn'?t be allowed to (live|breed|exist|vote)|go back (where|to) (you|your)|kill yourself|\bkys\b|subhuman|vermin|\bretard|\bidiot|\bmoron|you('re| are) (worthless|garbage|trash|scum|pathetic)|i('ll| will) (kill|find|hurt) you|идиот|дебил|кретин|\bурод|мразь|тварь|сдохни|\bубью|ублюд|\bчмо\b|быдло|тупая (овца|корова)|не должны (жить|размножаться)|вали (отсюда|в свою)`)
	impRe     = regexp.MustCompile(`(?i)(it'?s|this is|i'?m) [a-z]+ from (accounting|finance|it|hr|payroll|legal|the ceo|management|security|the bank)|это [а-яё]+ из (бухгалтерии|финотдела|it|айти|отдела кадров|службы безопасности|банка)|ceo here|i'?m the (ceo|cfo|director)|я (директор|генеральный)`)
	urgRe     = regexp.MustCompile(`(?i)\basap\b|urgent|immediately|right now|within (the hour|\d+ min)|срочно|немедленно|прямо сейчас|в течение часа`)
	pmailRe   = regexp.MustCompile(`(?i)@(gmail|yahoo|outlook|hotmail|proton(mail)?|mail|yandex|icloud|aol)\.`)
	sendRe    = regexp.MustCompile(`(?i)(email|send|share|forward|wire|transfer|buy) (it|me|the|us|over|\$|\d)|(gift ?cards?)|(пришли|скинь|отправь|переведи|перешли|купи)`)
	lockRe    = regexp.MustCompile(`(?i)locked out|lost access|new (phone|number)|can'?t access|не могу (зайти|войти)|потерял доступ|новый номер|keep (this|it) (between us|quiet|confidential)|никому не говори`)
	qLangRe   = regexp.MustCompile(`language|язык`)
	qViolRe   = regexp.MustCompile(`violate|guideline|community rules|moderat|правил[а-я]* сообществ|наруша`)
	cardRunRe = regexp.MustCompile(`(?:^|[^\d])((?:\d[ -]?){12,18}\d)(?:[^\d]|$)`)
	cardGrpRe = regexp.MustCompile(`^\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}(?:[ -]\d{3})?$|^\d{4}[ -]\d{6}[ -]\d{5}$`)
	emailRe   = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
	phoneRe   = regexp.MustCompile(`(?:\+\d{1,3}[\s(-]*|\b8[\s(-]*)\d{3}[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}\b|\+\d{1,3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{4}\b`)
	passRe    = regexp.MustCompile(`(?i)(паспорт|passport)[^\n]{0,20}?(\d{2}\s?\d{2}\s?\d{6}|[a-z]{1,2}\d{6,8})`)
	snilsRe   = regexp.MustCompile(`\b\d{3}-\d{3}-\d{3}[ -]\d{2}\b`)
	ibanRe    = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}\b`)
	ssnRe     = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	injRe     = regexp.MustCompile(`(?i)ignore (all |any |the )?(previous|prior|above|earlier|your)? ?(instructions|rules|prompts?)|disregard (all |the )?(previous|prior|above)|forget (all |your )?(previous )?(instructions|rules)|you are now (dan|an? unrestricted)|\bdan\b.*no rules|developer mode|system prompt|\[system\]|<\s*system\s*>|new instructions?:|(reveal|print|send|leak|exfiltrate)[^.]{0,40}(password|api key|secret|token|credentials|system prompt)|игнорируй (все |всё |любые )?(предыдущ|прошл|прежн|инструкц|правил)|забудь (все |всё )?(предыдущ|инструкц|правил)|не обращай внимания на (предыдущ|инструкц)|ты теперь dan|новая инструкция|новые инструкции|системн(ый|ая) (промпт|инструкц)|(раскрой|покажи|отправь|перешли)[^.]{0,40}(парол|ключ|токен|секрет|промпт)|<!--[^>]*(instruction|инструкц|ignore|игнорир|assistant|ассистент|\bai\b|\bии\b|agent|агент|llm|model|модел)|\b(ai|llm) (agents?|assistants?|models?) reading this|(email|send|forward|upload) (the |all )?user'?s (calendar|contacts|files|emails|data|password)|(отправь|перешли) (все |всё )?(контакты|письма|файлы|данные) пользователя|(note|message|instructions?|command)s? (to|for) (the )?(ai|assistant|agent|llm|model|bot)\b|(open|access|read|search) the user'?s (inbox|email|mailbox|files|drive|contacts)|forward (the )?(latest|last|all|recent)? ?\d* ?(emails|messages|files)|(примечание|сообщение|инструкция|команда) для (ии|ai|ассистента|агента|модели|бота)|открой (почту|входящие|файлы) пользователя`)
	scamRe    = regexp.MustCompile(`(?i)код из (смс|sms)|назовите код|cvv|cvc|pin[- ]?код|ваша карта заблокирован|служба безопасности банка|подтвердите (данные|личность) по ссылке|verify your (account|identity)|account (has been )?(suspended|locked)|you('ve| have) won|вы выиграли|ваш выигрыш|gift ?cards?|seed phrase|сид-фраз|double your (crypto|bitcoin)|удвои[мт]`)
	spamRe    = regexp.MustCompile(`(?i)cheap|followers|подписчик|лайк[иов]* за|buy now|купи(те)? (сейчас|недорого)|скидк[аи] \d+|discount|promo ?code|промокод|earn \$|заработ[а-я]* от \d|casino|казино|viagra|crypto signals|\d+k for \$|click here|переходи(те)? по ссылке|одобрен[а-я]* (кредит|займ)|кредит без|займ без|без справок|заберите (деньги|приз|подарок)|limited (time )?offer|act now|только сегодня|успейте`)
	qApolRe   = regexp.MustCompile(`apologi[sz]e|say sorry|извинил|извинени`)
	qRefundRe = regexp.MustCompile(`refund|money back|вернуть деньги|возврат[а-я]* (денег|средств)`)
	apolRe    = regexp.MustCompile(`(?i)\bsorry\b|apologi|my apologies|i regret|извин|прошу прощения|простите|сожалеем|сожалею|приносим (свои )?извинения`)
	refundRe  = regexp.MustCompile(`(?i)refund|money back|reimburs|chargeback|верн(уть|ите|ете)[^.]{0,20}(деньги|средства|оплат)|возврат[а-я]* (денег|средств|оплаты)|хочу возврат|оформите возврат`)
	turnRe    = regexp.MustCompile(`(?im)^\s*(user|customer|client|пользователь|клиент|assistant|bot|agent|ассистент|бот|оператор|support|поддержка)\s*:\s*(.*)$`)
	linkRe    = regexp.MustCompile(`(?i)https?://|www\.|\b[a-z0-9-]+\.(com|biz|ru|net|io|xyz|top|info|online|shop|site|click)\b|t\.me/|\b(bit\.ly|tinyurl\.com|goo\.gl|clck\.ru|vk\.cc|cutt\.ly)/`)
)

func (Basics) Answer(_ any, stateText string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	qt := text(q)
	st := stateText
	if a, ok := groundAnswer(st, q, qt); ok {
		return a, true
	}
	switch q.Type {
	case s1.TypeNoul:
		switch {
		case qCardRe.MatchString(qt):
			if ev, luhnOK, ok := findCard(st); ok {
				p := 0.95
				if luhnOK {
					p = 0.985
				}
				return yes(p, "номер карты: "+mask(ev)), true
			}
			if !strings.ContainsFunc(st, unicode.IsDigit) || !regexp.MustCompile(`\d{4}`).MatchString(strings.ReplaceAll(st, " ", "")) {
				return yes(0.03, "в тексте нет последовательности цифр, похожей на номер карты"), true
			}
			return s1.ExpertAnswer{}, false
		case qFollowRe.MatchString(qt):
			if m := injRe.FindString(st); m != "" {
				return yes(0.04, "это инструкция внутри данных, ей нельзя следовать: «"+clip(m)+"»"), true
			}
			return s1.ExpertAnswer{}, false
		case qPhishRe.MatchString(qt) || qFulfilRe.MatchString(qt):
			ev := scamRe.FindString(st)
			if ev == "" {
				ev = socEng(st)
			}
			if ev == "" {
				return s1.ExpertAnswer{}, false
			}
			if qPhishRe.MatchString(qt) {
				return yes(0.93, "признаки мошенничества: "+clip(ev)), true
			}
			return yes(0.06, "похоже на мошенничество, выполнять нельзя: "+clip(ev)), true
		case qSpamRe.MatchString(qt) || qReplyRe.MatchString(qt):
			ev := scamRe.FindString(st)
			if m := spamRe.FindString(st); ev == "" && m != "" && linkRe.MatchString(st) {
				ev = m
			}
			if ev == "" {
				return s1.ExpertAnswer{}, false
			}
			if qSpamRe.MatchString(qt) {
				return yes(0.93, "реклама/спам: «"+clip(ev)+"»"), true
			}
			return yes(0.07, "это спам, отвечать не нужно: «"+clip(ev)+"»"), true
		case qToxRe.MatchString(qt):
			if m := toxRe.FindString(st); m != "" {
				return yes(0.94, "оскорбление/язык вражды: «"+clip(m)+"»"), true
			}
			return s1.ExpertAnswer{}, false
		case qPIIRe.MatchString(qt):
			if ev := findPII(st); ev != "" {
				return yes(0.97, ev), true
			}
			return s1.ExpertAnswer{}, false
		case qInjRe.MatchString(qt):
			if m := injRe.FindString(st); m != "" {
				return yes(0.95, "инструкция внутри данных: «"+clip(m)+"»"), true
			}
			return s1.ExpertAnswer{}, false
		case qApolRe.MatchString(qt) && strings.Contains(qt, "assist") || strings.Contains(qt, "ассистент") && qApolRe.MatchString(qt):
			if _, bot, ok := turns(st); ok {
				if m := apolRe.FindString(bot); m != "" {
					return yes(0.95, "ассистент: «"+clip(m)+"»"), true
				}
				return yes(0.06, "в репликах ассистента нет извинений"), true
			}
		case qRefundRe.MatchString(qt) && (strings.Contains(qt, "user") || strings.Contains(qt, "пользовател") || strings.Contains(qt, "customer") || strings.Contains(qt, "клиент")):
			if user, _, ok := turns(st); ok {
				if m := refundRe.FindString(user); m != "" {
					return yes(0.94, "пользователь: «"+clip(m)+"»"), true
				}
			}
		case qViolRe.MatchString(qt):
			if m := scamRe.FindString(st); m != "" {
				return yes(0.93, "признак мошенничества: «"+clip(m)+"»"), true
			}
			if m := spamRe.FindString(st); m != "" && linkRe.MatchString(st) {
				return yes(0.92, "реклама со ссылкой: «"+clip(m)+"»"), true
			}
		}
	case s1.TypeChoice:
		if lang := langOptions(q.Options); lang != nil && qLangRe.MatchString(qt) {
			code, why := detectLang(st)
			if i, ok := lang[code]; ok {
				return peaked(len(q.Options), i, 0.9, "язык: "+why), true
			}
			return s1.ExpertAnswer{}, false
		}
		idx := map[string]int{}
		for i, o := range q.Options {
			idx[strings.ToLower(o.Key)] = i
		}
		if i, ok := idx["scam"]; ok {
			if m := scamRe.FindString(st); m != "" {
				return peaked(len(q.Options), i, 0.88, "признак мошенничества: «"+clip(m)+"»"), true
			}
		}
		if i, ok := idx["spam"]; ok {
			if m := spamRe.FindString(st); m != "" && linkRe.MatchString(st) {
				return peaked(len(q.Options), i, 0.88, "реклама со ссылкой: «"+clip(m)+"»"), true
			}
		}
	}
	return s1.ExpertAnswer{}, false
}

// socEng flags classic business-email-compromise / pretexting: at least two of impersonation,
// urgency, a personal-mailbox destination, a lockout/secrecy pretext, combined with a send request.
func socEng(s string) string {
	var hits []string
	for _, c := range []struct {
		re   *regexp.Regexp
		what string
	}{{impRe, "представляется коллегой"}, {urgRe, "срочность"}, {pmailRe, "личная почта"}, {lockRe, "предлог/секретность"}} {
		if c.re.MatchString(s) {
			hits = append(hits, c.what)
		}
	}
	if len(hits) >= 2 && sendRe.MatchString(s) {
		return strings.Join(hits, ", ") + " + просьба что-то отправить"
	}
	return ""
}

func yes(p float64, ev string) s1.ExpertAnswer {
	return s1.ExpertAnswer{Probs: []float64{p}, Evidence: []string{ev}, Source: "basics-rule", Calibrated: true}
}

func peaked(n, i int, p float64, ev string) s1.ExpertAnswer {
	pr := make([]float64, n)
	for j := range pr {
		pr[j] = (1 - p) / float64(max(1, n-1))
	}
	pr[i] = p
	return s1.ExpertAnswer{Probs: pr, Evidence: []string{ev}, Source: "basics-rule", Calibrated: true}
}

func clip(s string) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > 60 {
		return string(r[:60]) + "…"
	}
	return string(r)
}

func mask(s string) string {
	d := []rune(s)
	n := 0
	for i := len(d) - 1; i >= 0; i-- {
		if unicode.IsDigit(d[i]) {
			n++
			if n > 4 {
				d[i] = '•'
			}
		}
	}
	return string(d)
}

// findCard returns the first digit run that looks like a payment card (13–19 digits, contiguous or
// grouped by 4) and whether it passes the Luhn check.
func findCard(s string) (string, bool, bool) {
	for _, m := range cardRunRe.FindAllStringSubmatch(s, -1) {
		run := strings.TrimSpace(m[1])
		digits := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return r
			}
			return -1
		}, run)
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if run != digits && !cardGrpRe.MatchString(run) {
			continue // e.g. phone numbers or dates glued together
		}
		if strings.HasPrefix(digits, "00") || (run == digits && !luhn(digits)) {
			continue // international dialling prefix / arbitrary ids
		}
		return run, luhn(digits), true
	}
	return "", false, false
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func findPII(s string) string {
	if ev, _, ok := findCard(s); ok {
		return "номер карты: " + mask(ev)
	}
	for _, c := range []struct {
		re   *regexp.Regexp
		what string
	}{{emailRe, "email"}, {phoneRe, "телефон"}, {passRe, "паспорт"}, {snilsRe, "СНИЛС"}, {ssnRe, "SSN"}, {ibanRe, "IBAN"}} {
		if c.re.MatchString(s) {
			return "персональные данные: " + c.what
		}
	}
	return ""
}

// ---------- language identification ----------

var langNames = map[string]string{
	"en": "en", "english": "en", "английский": "en", "ru": "ru", "russian": "ru", "русский": "ru",
	"de": "de", "german": "de", "немецкий": "de", "fr": "fr", "french": "fr", "французский": "fr",
	"es": "es", "spanish": "es", "испанский": "es", "it": "it", "italian": "it", "итальянский": "it",
	"pt": "pt", "portuguese": "pt", "uk": "uk", "ukrainian": "uk", "украинский": "uk", "pl": "pl", "polish": "pl",
	"nl": "nl", "dutch": "nl", "tr": "tr", "turkish": "tr", "mixed": "mixed", "смешанный": "mixed",
}

func langOptions(opts []s1.Option) map[string]int {
	m := map[string]int{}
	for i, o := range opts {
		c, ok := langNames[strings.ToLower(o.Key)]
		if !ok {
			return nil
		}
		m[c] = i
	}
	if len(m) < 2 {
		return nil
	}
	return m
}

var stop = map[string][]string{
	"en": {"the", "and", "is", "are", "you", "to", "of", "please", "can", "my", "i", "it", "this", "for", "with", "what", "your", "we", "have"},
	"de": {"der", "die", "das", "und", "ist", "ich", "nicht", "bitte", "kannst", "du", "mir", "sie", "ein", "eine", "mit", "für", "wir", "haben", "rechnung", "schicken"},
	"fr": {"le", "la", "les", "et", "est", "je", "vous", "pas", "pour", "une", "un", "avec", "merci", "pouvez", "mon", "ma", "nous", "bonjour", "facture"},
	"es": {"el", "la", "los", "las", "y", "es", "que", "por", "favor", "puedes", "mi", "con", "para", "una", "un", "gracias", "hola", "no", "factura"},
	"it": {"il", "la", "che", "è", "per", "non", "una", "un", "con", "mi", "puoi", "grazie", "ciao", "sono", "della", "fattura"},
	"pt": {"o", "a", "que", "não", "para", "com", "uma", "um", "obrigado", "você", "por", "favor", "fatura"},
	"nl": {"de", "het", "een", "en", "is", "ik", "niet", "je", "met", "voor", "alsjeblieft", "factuur"},
	"pl": {"nie", "jest", "się", "na", "i", "w", "z", "proszę", "czy", "to", "mi", "faktura"},
	"tr": {"ve", "bir", "bu", "için", "lütfen", "mi", "ne", "değil", "fatura"},
}

func detectLang(s string) (string, string) {
	cyr, lat := 0, 0
	uk := false
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Cyrillic, r):
			cyr++
			if strings.ContainsRune("іїєґІЇЄҐ", r) {
				uk = true
			}
		case r < 0x250 && unicode.IsLetter(r):
			lat++
		}
	}
	if cyr+lat == 0 {
		return "", "нет букв"
	}
	if min(cyr, lat) > 0 && float64(min(cyr, lat))/float64(cyr+lat) > 0.25 {
		return "mixed", "кириллица и латиница вперемешку"
	}
	if cyr > lat {
		if uk {
			return "uk", "кириллица с і/ї/є"
		}
		return "ru", "кириллица"
	}
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) })
	best, bn := "en", 0
	for _, l := range []string{"en", "de", "fr", "es", "it", "pt", "nl", "pl", "tr"} {
		n := 0
		for _, w := range words {
			for _, sw := range stop[l] {
				if w == sw {
					n++
					break
				}
			}
		}
		if n > bn {
			best, bn = l, n
		}
	}
	for _, r := range s { // diacritics are strong hints
		switch {
		case strings.ContainsRune("äöüß", unicode.ToLower(r)):
			return "de", "умляуты"
		case strings.ContainsRune("ñ¿¡", unicode.ToLower(r)):
			return "es", "ñ/¿"
		case strings.ContainsRune("ąęłńśźż", unicode.ToLower(r)):
			return "pl", "польские буквы"
		case strings.ContainsRune("ğış", unicode.ToLower(r)):
			return "tr", "турецкие буквы"
		}
	}
	return best, "латиница, служебные слова"
}

// turns splits a "user: … / assistant: …" transcript into the user's and the assistant's text.
func turns(s string) (user, bot string, ok bool) {
	var u, b strings.Builder
	for _, m := range turnRe.FindAllStringSubmatch(s, -1) {
		switch strings.ToLower(m[1]) {
		case "user", "customer", "client", "пользователь", "клиент":
			u.WriteString(m[2] + "\n")
		default:
			b.WriteString(m[2] + "\n")
		}
	}
	return u.String(), b.String(), u.Len() > 0 && b.Len() > 0
}
