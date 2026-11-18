// Package experts plugs DecisionAI's specialised models and deterministic checks into System One.
// Order matters: deterministic checks first, then trained domain models, then (outside this package)
// the general text backend.
package experts

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"decisionai/s1"
	"decisionai/smalirole"
	"decisionai/textai"
)

// Default returns the standard expert chain. Nil models disable the experts that need them.
func Default(role *smalirole.Model, text *textai.Model) []s1.Expert {
	ex := []s1.Expert{NeuralRole{Model: role}, Server{}, Checks{}, SourceEvidence{}, Finding{}, Role{Model: role}, Game{}, ToolProperties{}, Reasoning{}, Basics{}, Quantity{}, Math{}}
	if text != nil {
		ex = append(ex, TextAI{Model: text})
	}
	return ex
}

// ---------- state helpers ----------

// fields flattens state JSON into lower-case dotted paths.
func fields(state any) map[string]any {
	out := map[string]any{}
	scope := ""
	if obj, ok := state.(map[string]any); ok {
		if current, exists := obj["current"]; exists {
			selected, ok := current.(map[string]any)
			if !ok {
				return out
			}
			state, scope = selected, "current"
		}
	}
	var walk func(p string, v any)
	walk = func(p string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				q := strings.ToLower(k)
				if p != "" {
					q = p + "." + q
				}
				walk(q, x)
			}
		case []any:
			for i, x := range t {
				walk(fmt.Sprintf("%s[%d]", p, i), x)
			}
		default:
			out[p] = v
		}
	}
	walk(scope, state)
	return out
}

// find returns the first field whose path equals or ends with one of names (".name"), in names order.
func find(f map[string]any, names ...string) (string, any, bool) {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, n := range names {
		for _, k := range keys {
			if k == n || k == "current."+n {
				return k, f[k], true
			}
		}
	}
	return "", nil, false
}

type status int

const (
	unknown status = iota
	pass
	fail
	notRun
)

func statusOf(v any) status {
	switch t := v.(type) {
	case bool:
		if t {
			return pass
		}
		return fail
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		switch s {
		case "pass", "passed", "ok", "success", "succeeded", "green", "true", "yes", "да", "успешно", "прошла", "прошёл", "прошел":
			return pass
		case "fail", "failed", "error", "red", "false", "no", "нет", "ошибка", "упала", "упал", "crash", "crashed":
			return fail
		case "not_run", "notrun", "skipped", "skip", "none", "pending", "missing", "не запускался", "не запускалась":
			return notRun
		}
	}
	return unknown
}

func text(q s1.ExpertQuestion) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(q.Instr))
	for _, o := range q.Options {
		b.WriteString(" " + strings.ToLower(o.Key+" "+o.Text))
	}
	return b.String()
}

func show(path string, v any) string { return fmt.Sprintf("%s: %v", path, v) }

// ---------- 1. Checks: build / runtime / SHA / effect_verified (deterministic) ----------

// Checks answers "was the patch effect confirmed?" from structured build/test records,
// following the legacy gate: no successful build + test on the *current* candidate, no confirmation.
type Checks struct{}

func (Checks) Name() string { return "checks-rule" }

var confirmRe = regexp.MustCompile(`эффект|effect|подтвержд|confirm|сработал|works?\b|работает|патч|patch|verified|провер`)

func (Checks) Answer(state any, _ string, q s1.ExpertQuestion) (answer s1.ExpertAnswer, handled bool) {
	if q.Type != s1.TypeNoul || (q.Task != "" && q.Task != s1.TaskPatchEffect) || (q.Task == "" && (!confirmRe.MatchString(text(q)) || serverRe.MatchString(strings.ToLower(q.Instr)))) {
		return s1.ExpertAnswer{}, false
	}
	negative, known := noulMeaning(q, s1.TaskPatchEffect)
	if !known {
		if _, textOnly := state.(string); textOnly && q.Task == "" {
			// a free-text state with a question that merely mentions "подтверждение" /
			// "check" (e.g. "без подтверждения человека") is not a patch-effect question:
			// leave it to the general model instead of answering 0.5
			return s1.ExpertAnswer{}, false
		}
		return uncertain(q, "unsupported_question", "Уточните смысл вопроса или задайте task=patch_effect."), true
	}
	defer func() {
		if handled {
			if negative && len(answer.Probs) > 0 {
				answer.Probs[0] = 1 - answer.Probs[0]
			}
			answer.References = evidenceReferences(answer.Evidence, state)
		}
	}()
	f := fields(state)
	bp, bv, hasB := find(f, "build.status", "build_status", "build")
	rp, rv, hasR := find(f, "runtime.status", "runtime_status", "runtime", "test.status", "tests.status", "behavior_test", "test", "tests")
	sp, sv, hasS := find(f, "sha256_matches", "sha_matches", "hash_matches", "build.sha256_matches")
	ep, evv, hasE := find(f, "effect_verified", "effect_confirmed", "effect_observed")
	if !hasB && !hasR && !hasE {
		if _, textOnly := state.(string); textOnly && q.Task == "" {
			return s1.ExpertAnswer{}, false
		}
		a := uncertain(q, "missing_run", "Нет результатов текущего запуска.")
		a.Checks = patchChecks(f)
		return a, true
	}
	shaOK, shaPath := unknown, sp
	if hasS {
		shaOK = statusOf(sv)
	} else if tp, tv, ok := find(f, "tested_sha256"); ok {
		shaPath = tp
		if _, cv, ok := find(f, "candidate_code"); ok {
			if c, ok := cv.(string); ok && c != "" {
				if strings.EqualFold(fmt.Sprint(tv), textai.SHA256(c)) {
					shaOK = pass
				} else {
					shaOK = fail
				}
			}
		} else if _, cv, ok := find(f, "candidate_sha256", "current_sha256"); ok {
			if strings.EqualFold(fmt.Sprint(tv), fmt.Sprint(cv)) {
				shaOK = pass
			} else {
				shaOK = fail
			}
		}
	}
	no := func(why string) (s1.ExpertAnswer, bool) {
		return s1.ExpertAnswer{Probs: []float64{0.02}, Evidence: []string{why}, Calibrated: true, Reason: "checks_failed", Checks: patchChecks(f)}, true
	}
	b, r, e := statusOf(bv), statusOf(rv), statusOf(evv)
	switch {
	case hasB && b == fail:
		return no(show(bp, bv) + ", сборка не прошла")
	case hasR && r == fail:
		return no(show(rp, rv) + ", тест поведения упал")
	case shaOK == fail:
		return no(show(shaPath, "≠ текущий кандидат") + ", тест шёл на другой версии")
	case hasE && e == fail:
		return no(show(ep, evv))
	case hasB && b == notRun:
		return no(show(bp, bv) + ", сборка не запускалась")
	case hasR && r == notRun:
		return no(show(rp, rv) + ", тест не запускался")
	}
	if b == pass && r == pass && shaOK != fail {
		ev := []string{show(bp, bv), show(rp, rv)}
		if shaOK == pass {
			ev = append(ev, show(shaPath, "совпадает"))
		}
		if hasE && e == pass && shaOK == pass {
			return s1.ExpertAnswer{Probs: []float64{0.98}, Evidence: append(ev, show(ep, evv)), Calibrated: true}, true
		}
		// build + runtime passed on this build, but the effect itself is only described in free text
		p := 0.85
		if shaOK != pass {
			p = 0.7 // cannot tell that the test ran on the current candidate
		}
		return s1.ExpertAnswer{Probs: []float64{p}, Evidence: append(ev, "Не хватает подтверждения эффекта или идентичности сборки."), Reason: "incomplete_run_evidence", Checks: patchChecks(f)}, true
	}
	return s1.ExpertAnswer{}, false
}

// ---------- 2. Server dependency ----------

// Server answers "how much does this depend on the server?" from a server_dependency field,
// a network-request counter, or explicit statements in the notes.
type Server struct{}

func (Server) Name() string { return "server-rule" }

var (
	serverRe     = regexp.MustCompile(`сервер|server|сетев|сети|network|онлайн|online|backend|бэкенд`)
	netNoneRe    = regexp.MustCompile(`(сетев\S*\s+(запрос\S*|обращени\S*|трафик\S*)|запрос\S*\s+к\s+сервер\S*|обращени\S*\s+к\s+сервер\S*|network\s+(requests?|calls?|traffic)|server\s+(requests?|calls?))[^.;]{0,25}(не\s+было|нет([\s.,;!]|$)|отсутств|не\s+обнаруж|не\s+выполнял|none|0\b|were\s+not|no\b)|(нет|без|no|without|zero)\s+(сетев\S*|сети([\s.,;!]|$)|network|сервер\S*\s+(запрос|огранич|провер)|server\s+(requests?|calls?|checks?))|offline|офлайн|оффлайн|серверного\s+ограничения\s+нет|полностью\s+локальн|fully\s+local|сеть\s+(отключена|выключена)|network\s+(disabled|off)|airplane\s+mode|авиарежим`)
	netServerRe  = regexp.MustCompile(`сервер\S*\s+(провер\S*|валидир\S*|решает|возвращ\S*|подтвержд\S*|перезапис\S*|сбрасыва\S*)|server\s+(validates|checks|decides|returns|overrides|resets)|значение\s+приходит\s+с\s+сервера|value\s+comes\s+from\s+(the\s+)?server`)
	netDecidesRe = regexp.MustCompile(`(рассчитыва\S*|вычисля\S*|хранится|определя\S*)\s+на\s+(стороне\s+)?сервер|клиент\s+только\s+(отображает|показывает)|(computed|calculated|stored|decided)\s+(on|by)\s+the\s+server|client\s+only\s+(displays|shows)`)
	netCacheRe   = regexp.MustCompile(`кэш\S*\s+(с|от)\s+сервер|cached?\s+from\s+(the\s+)?server|server\s+cache`)
)

// level: 0 local, 1 cache, 2 server checks, 3 server decides.
var levelWords = [][]string{
	{"локальн", "local", "offline", "офлайн", "не зависит", "нет зависим", "independent", "none", "нет"},
	{"кэш", "cache"},
	{"провер", "валид", "validat", "verif", "check"},
	{"решает", "decid", "authorit", "управля", "controls", "источник"},
}

func (Server) Answer(state any, stateText string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	instr := strings.ToLower(q.Instr)
	if (q.Task != "" && q.Task != s1.TaskServerDependency) || (q.Task == "" && !serverRe.MatchString(instr)) || q.Type == s1.TypeChoice {
		return s1.ExpertAnswer{}, false
	}
	f := fields(state)
	level, why, structured := -1, "", false
	if p, v, ok := find(f, "server_dependency", "server_dep", "server"); ok {
		s := strings.ToLower(fmt.Sprint(v))
		switch {
		case s == "false" || strings.Contains(s, "local") || s == "none" || s == "no":
			level = 0
		case strings.Contains(s, "cache"):
			level = 1
		case strings.Contains(s, "valid") || strings.Contains(s, "check") || s == "true":
			level = 2
		case strings.Contains(s, "decid") || strings.Contains(s, "author"):
			level = 3
		}
		if level >= 0 {
			why, structured = show(p, v), true
		}
	}
	if level < 0 {
		if p, v, ok := find(f, "network_requests", "network_calls", "server_requests", "requests_to_server"); ok {
			n, err := strconv.ParseFloat(fmt.Sprint(v), 64)
			if (err == nil && n == 0) || v == false {
				a := uncertain(q, "no_network_evidence", "Ноль запросов не доказывает независимость от сервера.")
				a.Evidence = []string{show(p, v)}
				a.Checks = []s1.NextCheck{{ID: "network_scenario", Title: "Проверить сценарий с записью сетевых событий", Why: "Нужны завершённый запуск и сведения о покрытии сценария.", Kind: "runtime"}}
				a.References = evidenceReferences(a.Evidence, state)
				return a, true
			}
		}
	}
	if level < 0 {
		stateText = scopedText(state, stateText)
		low := strings.ToLower(stateText)
		switch {
		case netDecidesRe.MatchString(low):
			level, why = 3, quote(stateText, netDecidesRe)
		case netServerRe.MatchString(low):
			level, why = 2, quote(stateText, netServerRe)
		case netCacheRe.MatchString(low):
			level, why = 1, quote(stateText, netCacheRe)
		case netNoneRe.MatchString(low):
			level, why = 0, quote(stateText, netNoneRe)
		}
	}
	if level < 0 {
		if q.Task == s1.TaskServerDependency {
			return uncertain(q, "missing_network_evidence", "Нет данных о зависимости от сервера."), true
		}
		return s1.ExpertAnswer{}, false
	}
	ev := []string{why}
	// a declared field (like build/runtime records) is trusted the same way the checks rule trusts them
	cal := structured
	if _, v, ok := find(f, "runtime.status", "runtime", "runtime_status"); ok && statusOf(v) != pass {
		cal = false
	}
	if q.Type == s1.TypeNoul {
		negative, known := noulMeaning(q, s1.TaskServerDependency)
		if !known {
			return uncertain(q, "unsupported_question", "Уточните, спрашивается ли зависимость от сервера или её отсутствие."), true
		}
		p := map[int]float64{0: 0.04, 1: 0.5, 2: 0.9, 3: 0.96}[level]
		if negative {
			p = 1 - p
		}
		return s1.ExpertAnswer{Probs: []float64{p}, Evidence: ev, Calibrated: cal, References: evidenceReferences(ev, state)}, true
	}
	// score: pick the option describing this level (by words), else by position
	n := len(q.Options)
	target := -1
	for i, o := range q.Options {
		t := strings.ToLower(o.Text)
		for _, w := range levelWords[level] {
			if strings.Contains(t, w) {
				target = i
				break
			}
		}
		if target >= 0 {
			break
		}
	}
	if target < 0 {
		target = int(float64(level)/3*float64(n-1) + 0.5)
	}
	main := 0.9
	if !structured {
		main = 0.8
	}
	probs := make([]float64, n)
	rest := 0.0
	for i := range probs {
		if i != target {
			d := float64(i - target)
			if d < 0 {
				d = -d
			}
			probs[i] = 1 / (d * d)
			rest += probs[i]
		}
	}
	for i := range probs {
		if i == target {
			probs[i] = main
		} else {
			probs[i] *= (1 - main) / rest
		}
	}
	return s1.ExpertAnswer{Probs: probs, Evidence: ev, Calibrated: cal, References: evidenceReferences(ev, state)}, true
}

func quote(s string, re *regexp.Regexp) string {
	low := strings.ToLower(s)
	loc := re.FindStringIndex(low)
	if loc == nil {
		return ""
	}
	// expand to the sentence (byte offsets are equal: ToLower keeps lengths for RU/EN letters)
	a, b := loc[0], loc[1]
	if len(low) != len(s) {
		return strings.TrimSpace(low[a:b])
	}
	for a > 0 && !strings.ContainsRune(".!?\n", rune(s[a-1])) {
		a--
	}
	for b < len(s) && !strings.ContainsRune(".!?\n", rune(s[b])) {
		b++
	}
	return strings.TrimSpace(s[a:b])
}

// ---------- 3. Literal role (smalirole) ----------

// Role answers "what role does this literal play?" with the trained smalirole model
// (logistic regression + R-GCN, calibrated on held-out apps) and maps its labels onto the declared options.
type Role struct{ Model *smalirole.Model }

func (Role) Name() string { return "smalirole" }

var (
	roleQRe   = regexp.MustCompile(`литерал|констант|literal|constant|роль|role|значени|value|число|number`)
	snippetRe = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\([^)]*\)\S*\s+(const[\w/-]*)\s+(v\d+|p\d+)\s*,\s*(-?0x[0-9a-fA-F]+|-?\d+)`)
	constRe   = regexp.MustCompile(`^\s*const[\w/-]*\s+[vp]\d+\s*,\s*\S+`)
)

// labelWords maps smalirole labels onto option wording (RU/EN).
var labelWords = map[string][]string{
	"limit_threshold": {"лимит", "максим", "миним", "порог", "предел", "огранич", "limit", "max", "min", "threshold", "cap", "bound"},
	"duration_ms":     {"задерж", "таймер", "таймаут", "время", "длительн", "интервал", "delay", "timer", "timeout", "duration", "interval", "time"},
	"color_argb":      {"цвет", "color", "colour", "argb", "rgb"},
	"resource_id":     {"ресурс", "resource", "res_id", "r.id", "идентификатор"},
	"boolean":         {"bool", "логич", "true/false", "флаг", "flag", "включ", "toggle"},
	"flag_bit":        {"флаг", "flag", "бит", "bit"},
	"bitmask":         {"маск", "mask", "бит", "bit"},
	"counter_step":    {"шаг", "счётчик", "счетчик", "инкремент", "step", "increment", "counter"},
	"index_or_size":   {"размер", "индекс", "длина", "size", "index", "length", "count", "количеств"},
	"sentinel":        {"sentinel", "маркер", "специальн", "отсутств", "-1"},
	"api_constant":    {"api", "sdk", "enum", "код", "code", "mode", "режим"},
	"layout_param":    {"layout", "разметк", "match_parent", "wrap_content"},
}

var escapeRe = regexp.MustCompile(`other|none|neither|unknown|другое|иное|прочее|ничего|не определ|нет подходящ`)

func (r Role) Answer(state any, _ string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if q.Type != s1.TypeChoice || r.Model == nil ||
		(q.Task != "" && q.Task != s1.TaskLiteralRole) ||
		(q.Task == "" && !roleQRe.MatchString(strings.ToLower(q.Instr))) {
		return s1.ExpertAnswer{}, false
	}
	mapping, escape, mapped := mapLabels(q.Options)
	if mapped < 2 {
		return s1.ExpertAnswer{}, false // the options are not about literal roles
	}
	f := fields(state)
	var dist map[string]float64
	var ev []string
	calibrated := false
	if code, line, ok := smaliCode(f); ok {
		rep, err := smalirole.AnalyzeCtx(smalirole.Request{Code: code, Line: line}, r.Model, &smalirole.Ctx{})
		if err != nil {
			return s1.ExpertAnswer{}, false
		}
		dist = map[string]float64{}
		for _, p := range rep.Probs {
			dist[p.Label] = p.P
		}
		calibrated = !strings.Contains(rep.Scorer, "unaudited")
		for i, e := range rep.Evidence {
			if i == 2 {
				break
			}
			ev = append(ev, fmt.Sprintf("строка %d: %s (%s)", e.Line, e.Text, e.Signal))
		}
		if len(ev) == 0 {
			ev = []string{rep.Explanation}
		}
	} else {
		// only a "getMaxCoins() const/16 v0, 0x64 → 0x3e8" description, no method body
		m := ""
		for _, v := range f {
			if s, ok := v.(string); ok {
				if mm := snippetRe.FindStringSubmatch(s); mm != nil {
					m = mm[1]
					break
				}
			}
		}
		lbl, ok := smalirole.NameVote(m)
		if !ok {
			return s1.ExpertAnswer{}, false
		}
		dist = map[string]float64{lbl: 0.65}
		for _, l := range smalirole.Labels {
			if l != lbl {
				dist[l] = 0.35 / float64(len(smalirole.Labels)-1)
			}
		}
		ev = []string{fmt.Sprintf("роль угадана по имени метода %s(). Кода метода в state нет, для точного ответа передайте поле code", m)}
	}
	probs := make([]float64, len(q.Options))
	for l, p := range dist {
		if i, ok := mapping[l]; ok {
			probs[i] += p
		} else if escape >= 0 {
			probs[escape] += p
		}
	}
	return s1.ExpertAnswer{Probs: probs, Evidence: ev, Calibrated: calibrated}, true
}

// mapLabels resolves canonical keys before aliases or legacy descriptions.
// A named role cannot absorb another role just because its prose mentions it.
// Ambiguous descriptions remain unmapped, so their mass can go to unknown.
func mapLabels(opts []s1.Option) (map[string]int, int, int) {
	roles := make([]string, len(opts))
	ranks := make([]int, len(opts))
	for i, o := range opts {
		roles[i], ranks[i] = literalRoleKey(o.Key)
	}
	// Equal-priority matches are ambiguous. Returning no mapping is stable
	// under permutations and never silently assigns mass to the first option.
	selectKey := func(label string) (index, rank int) {
		index = -1
		for i, role := range roles {
			if role != label {
				continue
			}
			if ranks[i] > rank {
				index, rank = i, ranks[i]
			} else if ranks[i] == rank {
				index = -1
			}
		}
		return
	}
	escape, escapeRank := selectKey("unknown")
	if escapeRank == 0 {
		matches := 0
		for i, o := range opts {
			if roles[i] == "" && escapeRe.MatchString(strings.ToLower(o.Key+" "+o.Text)) {
				escape = i
				matches++
			}
		}
		if matches != 1 {
			escape = -1
		}
	}
	m := make(map[string]int)
	used := make(map[int]bool)
	for _, label := range smalirole.Labels {
		if label == "unknown" {
			continue
		}
		index, rank := selectKey(label)
		if rank == 0 {
			matches := 0
			for i, o := range opts {
				if roles[i] != "" || i == escape {
					continue
				}
				text := strings.ToLower(o.Key + " " + o.Text)
				for _, word := range labelWords[label] {
					if strings.Contains(text, word) {
						index = i
						matches++
						break
					}
				}
			}
			if matches != 1 {
				index = -1
			}
		}
		if index >= 0 {
			m[label] = index
			used[index] = true
		}
	}
	return m, escape, len(used)
}

// Rank 2 is an exact model label; rank 1 is a supported legacy key.
// Descriptions are intentionally not inspected here.
func literalRoleKey(key string) (string, int) {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, label := range smalirole.Labels {
		if key == label {
			return label, 2
		}
	}
	var role string
	switch key {
	case "limit", "threshold", "max", "min":
		role = "limit_threshold"
	case "delay", "timer", "timeout", "duration":
		role = "duration_ms"
	case "color", "colour", "argb":
		role = "color_argb"
	case "resource", "res_id":
		role = "resource_id"
	case "bool":
		role = "boolean"
	case "mask":
		role = "bitmask"
	case "step", "increment", "counter":
		role = "counter_step"
	case "size", "index", "length":
		role = "index_or_size"
	case "api", "enum":
		role = "api_constant"
	case "layout":
		role = "layout_param"
	case "other", "none", "neither", "другое", "иное", "прочее":
		role = "unknown"
	default:
		return "", 0
	}
	return role, 1
}

// smaliCode finds a Smali method body in state and the const line to analyse.
func smaliCode(f map[string]any) (string, int, bool) {
	_, v, ok := find(f, "code", "smali", "candidate_code", "method")
	if !ok {
		return "", 0, false
	}
	code, _ := v.(string)
	if !strings.Contains(code, ".method") {
		return "", 0, false
	}
	if _, lv, ok := find(f, "line", "const_line"); ok {
		if n, err := strconv.Atoi(fmt.Sprint(lv)); err == nil {
			return code, n, true
		}
	}
	line := 0
	for i, l := range strings.Split(code, "\n") {
		if constRe.MatchString(l) {
			if line != 0 {
				return "", 0, false // several literals and no "line": ambiguous
			}
			line = i + 1
		}
	}
	return code, line, line != 0
}

// ---------- 4. Legacy text model (patch confirmation) ----------

// TextAI runs the trained patch-confirmation text classifier when no structured records exist.
type TextAI struct{ Model *textai.Model }

func (TextAI) Name() string { return "textai" }

func (t TextAI) Answer(state any, stateText string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	stateText = proseOf(state, stateText)
	if t.Model == nil || q.Type != s1.TypeNoul || len(q.Options) != 2 || !confirmRe.MatchString(text(q)) || serverRe.MatchString(strings.ToLower(q.Instr)) {
		return s1.ExpertAnswer{}, false
	}
	rep, err := textai.Analyze(textai.Request{TaskID: textai.Task, State: stateText, Question: q.Instr, TrueWhen: q.Options[0].Text, FalseWhen: q.Options[1].Text}, t.Model)
	if err != nil || rep.Prediction.Kind == "heuristic_score" {
		return s1.ExpertAnswer{}, false
	}
	for _, r := range rep.AbstentionReasons {
		if r != "confidence_below_threshold" && r != "gate_blocked" {
			return s1.ExpertAnswer{}, false // unreliable input (unknown vocabulary, truncation …)
		}
	}
	return s1.ExpertAnswer{Probs: []float64{rep.Prediction.Value}, Evidence: []string{rep.Explanation}, Source: "textai (" + rep.Prediction.Kind + ")"}, true
}

// proseOf keeps only the human-written text of a JSON state (code and hashes confuse the lexical model).
func proseOf(state any, fallback string) string {
	f := fields(state)
	if len(f) == 0 {
		return fallback
	}
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		s, ok := f[k].(string)
		if !ok || strings.Contains(k, "code") || strings.Contains(k, "smali") || strings.Contains(k, "sha") || strings.Contains(s, ".method") {
			continue
		}
		if len(strings.Fields(s)) >= 3 {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return fallback
	}
	return strings.Join(parts, " ")
}
