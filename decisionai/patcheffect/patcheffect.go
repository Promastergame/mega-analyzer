// Package patcheffect explains a single-literal Smali patch before it is applied:
//
//  1. what_it_does  — the role of the literal (from smalirole) plus the direction of the change,
//     grounded in the data-flow trace so it cannot claim an effect the code does not show;
//  2. success       — an interpretable likelihood that the change produces its intended effect, built from
//     named structural factors (never a promise); low factors are shown, not hidden;
//  3. effort        — a complexity band and a rough minute range for a developer to land the change safely.
//
// It never executes code and never applies anything (CanApply stays false). The literal rewrite itself
// is produced by engine.PlanPatch; this package only reasons about it.
package patcheffect

import (
	"fmt"
	"math"
	"strings"

	"decisionai/engine"
	"decisionai/smalirole"
)

const Version = "0.2.0"

type Request struct {
	Code             string `json:"code"`
	Line             int    `json:"line"`
	Expected         int64  `json:"expected"`
	Replacement      int64  `json:"replacement"`
	Target           string `json:"target,omitempty"`            // user's claimed intent (not trusted)
	ServerDependency bool   `json:"server_dependency,omitempty"` // declared by caller
	AppOwned         bool   `json:"app_owned,omitempty"`
	Library          bool   `json:"library,omitempty"`
	Class            string `json:"class,omitempty"` // optional Lcom/foo/Bar; of the method
}

type Factor struct {
	Name   string  `json:"name"`
	Weight float64 `json:"contribution"` // signed logit contribution
	Why    string  `json:"why"`
}

type Success struct {
	Probability float64  `json:"probability"`
	Band        string   `json:"band"` // low | partial | medium | high
	Factors     []Factor `json:"factors"`
	Caps        []string `json:"caps,omitempty"`
	Calibration string   `json:"calibration"`
}

type Effort struct {
	Level      string   `json:"level"` // trivial | low | medium | high
	MinMinutes int      `json:"min_minutes"`
	MaxMinutes int      `json:"max_minutes"`
	Drivers    []string `json:"drivers"`
	Note       string   `json:"note"`
}

type Report struct {
	Version    string            `json:"version"`
	Role       smalirole.Report  `json:"role"`
	WhatItDoes string            `json:"what_it_does"`
	ChangeKind string            `json:"change_kind"`
	Success    Success           `json:"success"`
	Effort     Effort            `json:"effort"`
	Plan       *engine.PatchPlan `json:"plan,omitempty"`
	Clamps     []Clamp           `json:"clamps,omitempty"`
	Effective  *int64            `json:"effective_value,omitempty"`
	Blocked    []string          `json:"blocked,omitempty"`
	Overwrites []Overwrite       `json:"field_overwrites,omitempty"` // other writes to the field the literal is stored in
}

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }

// changeKind names the direction of the literal change for the detected role.
func changeKind(role string, before, after int64) (kind, verb string) {
	inc := after > before
	switch role {
	case "boolean":
		if before == 0 && after != 0 {
			return "enable", "включает флаг (false → true)"
		}
		if before != 0 && after == 0 {
			return "disable", "выключает флаг (true → false)"
		}
		return "set", "меняет булево значение"
	case "limit_threshold":
		if inc {
			return "raise_limit", "поднимает порог/лимит"
		}
		return "lower_limit", "снижает порог/лимит"
	case "counter_step":
		if inc {
			return "raise_step", "увеличивает прибавляемое значение"
		}
		return "lower_step", "уменьшает прибавляемое значение"
	case "duration_ms":
		if inc {
			return "raise_duration", "увеличивает длительность/таймаут"
		}
		return "lower_duration", "сокращает длительность/таймаут"
	case "bitmask", "flag_bit":
		return "change_mask", "меняет набор задействованных битов"
	case "color_argb":
		return "change_color", "меняет цвет"
	case "index_or_size":
		return "change_size", "меняет индекс или размер"
	case "resource_id", "api_constant":
		return "repoint", "переключает на другой ресурс/константу API — высокий риск несовпадения типа"
	case "sentinel":
		return "change_sentinel", "меняет служебное значение-маркер — обычно ломает сравнения"
	}
	return "change_value", "меняет значение"
}

// Analyze builds the full report. model may be nil (expert-rule scoring is used instead).
func Analyze(req Request, model *smalirole.Model, resolve smalirole.Resolver) (Report, error) {
	return AnalyzeCtx(req, model, &smalirole.Ctx{Resolve: resolve})
}

// AnalyzeCtx is Analyze with app-wide lookups (callees + field reads, see smalirole.App.Ctx).
func AnalyzeCtx(req Request, model *smalirole.Model, ctx *smalirole.Ctx) (Report, error) {
	rr, err := smalirole.AnalyzeCtx(smalirole.Request{Code: req.Code, Line: req.Line, Class: req.Class}, model, ctx)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Version: Version, Role: rr}

	// Plan the literal rewrite (mechanical, no execution). Reuses the audited engine planner.
	pr := engine.PatchRequest{Line: req.Line, Expected: req.Expected, Replacement: req.Replacement, Target: req.Target}
	var plan *engine.PatchPlan
	var perr error
	if isWideLine(req.Code, req.Line) {
		plan, perr = planWide(req.Code, req.Line, req.Expected, req.Replacement)
	} else {
		plan, perr = engine.PlanPatch(req.Code, pr)
	}
	rep.Plan = plan

	rep.Clamps = FindClamps(req.Code, req.Line)
	if len(rep.Clamps) > 0 {
		e := Effective(req.Replacement, rep.Clamps)
		rep.Effective = &e
	}

	role := rr.Answer
	// A clamp proves the value is a bounded quantity; use it when the classifier abstained.
	if rr.Abstained && len(rep.Clamps) > 0 && rr.FloatValue == nil {
		role = "limit_threshold"
	}
	kind, verb := changeKind(role, req.Expected, req.Replacement)
	rep.ChangeKind = kind

	// --- what it does ---
	var w strings.Builder
	if rr.Abstained && role == rr.Answer {
		if rr.FloatValue != nil {
			fmt.Fprintf(&w, "Значение — float %gf, а патч меняет его как целое: смысл почти наверняка неверен. ", *rr.FloatValue)
		} else {
			fmt.Fprintf(&w, "Роль значения не установлена (уверенность %.0f%%), поэтому эффект патча неизвестен. ", 100*rr.Probs[0].P)
		}
	} else {
		fmt.Fprintf(&w, "Это %s. Патч %s", roleRU(role), verb)
		if role == "duration_ms" {
			fmt.Fprintf(&w, " (%s → %s, если это миллисекунды)", smalirole.HumanMillis(req.Expected), smalirole.HumanMillis(req.Replacement))
		} else if req.Expected != req.Replacement && role != "boolean" {
			fmt.Fprintf(&w, " (%d → %d)", req.Expected, req.Replacement)
		}
		w.WriteString(". ")
	}
	if rep.Effective != nil && *rep.Effective != req.Replacement {
		c := rep.Clamps[0]
		fmt.Fprintf(&w, "ВНИМАНИЕ: дальше стоит ограничитель (%s, строка %d, граница %d) — фактически получится %d, а не %d. ", c.How, c.Line, c.Bound, *rep.Effective, req.Replacement)
	}
	expl := rr.Explanation
	if role != rr.Answer { // role proven by a clamp: drop the classifier's abstain verdict, keep the trace
		if k := strings.Index(expl, " Вывод:"); k >= 0 {
			expl = expl[:k] + " Вывод: ограниченная величина (лимит) — это доказывает найденный ограничитель."
		}
	}
	w.WriteString(expl)
	rep.WhatItDoes = strings.TrimSpace(w.String())

	// --- blocking gates (same policy as engine) ---
	if !req.AppOwned {
		rep.Blocked = append(rep.Blocked, "не заявлено app_owned")
	}
	if req.Library {
		rep.Blocked = append(rep.Blocked, "код в библиотеке")
	}
	if perr != nil {
		rep.Blocked = append(rep.Blocked, "план не строится: "+perr.Error())
	}

	// --- success likelihood from named factors ---
	rep.Overwrites = FieldOverwrites(req, rr, ctx)
	if len(rep.Overwrites) > 0 {
		o := rep.Overwrites[0]
		more := ""
		if len(rep.Overwrites) > 1 {
			more = fmt.Sprintf(" (всего других записей поля: %d)", len(rep.Overwrites))
		}
		rep.WhatItDoes = fmt.Sprintf("ВНИМАНИЕ: значение кладётся в поле %s, но это поле перезаписывается в %s (строка %d метода: `%s`)%s — патч этой строки может не дойти до использования. ", shortField(o.Field), o.Method, o.Line, o.Text, more) + rep.WhatItDoes
	}
	rep.Success = successEstimate(req, rr, kind, perr, rep.Clamps, rep.Effective, rep.Overwrites)

	// --- effort / time ---
	rep.Effort = effortEstimate(req, rr, perr, role != rr.Answer, rep.Effective != nil && *rep.Effective != req.Replacement)
	if n := len(rep.Overwrites); n > 0 {
		rep.Effort.Drivers = append(rep.Effort.Drivers, fmt.Sprintf("поле перезаписывается в других местах (%d) — их тоже надо проверить или патчить", n))
		rep.Effort.MinMinutes += 10
		rep.Effort.MaxMinutes += 25
		if rep.Effort.Level == "trivial" || rep.Effort.Level == "low" {
			rep.Effort.Level = "medium"
		}
	}
	return rep, nil
}

func successEstimate(req Request, rr smalirole.Report, kind string, perr error, clamps []Clamp, eff *int64, ow []Overwrite) Success {
	var f []Factor
	bias := -0.2
	add := func(name string, w float64, why string) {
		f = append(f, Factor{name, round2(w), why})
	}

	// 1. Do we understand what the literal does? A clamped sigmoid of role confidence.
	rc := rr.Probs[0].P
	if rr.Abstained && len(clamps) > 0 && rr.FloatValue == nil {
		add("role_from_clamp", 0.6, "классификатор не уверен, но ограничитель доказывает, что это ограниченная величина (лимит)")
	} else if rr.Abstained {
		add("role_unknown", -1.6, fmt.Sprintf("роль не определена (топ %.0f%%) — непонятно, на что влияет патч", 100*rc))
	} else {
		add("role_understood", 1.4*(rc-0.5)/0.5, fmt.Sprintf("роль «%s» определена с уверенностью %.0f%%", rr.Answer, 100*rc))
	}

	// 2. Is the value actually used? A dead const never changes behaviour.
	nUses := len(rr.Evidence)
	if nUses == 0 {
		add("value_unused", -2.0, "значение не читается в методе — патч почти наверняка ни на что не влияет")
	} else {
		add("value_used", 0.5, fmt.Sprintf("значение действительно используется (%d мест)", nUses))
	}

	// 3. Float-as-int mistake.
	if rr.FloatValue != nil {
		add("float_mismatch", -2.2, "биты — это float, менять их как целое бессмысленно")
	}

	// 4. Server dependency: a local literal cannot override a server-side decision.
	if len(ow) > 0 {
		w := -0.8 // common: on the corpus 79% of literals stored into a field have another writer
		why := fmt.Sprintf("поле %s записывается ещё в других местах (%d; первое — %s) — значение из этой строки может быть затёрто", shortField(ow[0].Field), len(ow), ow[0].Method)
		if ow[0].DefaultOnly {
			w = -1.6
			why = fmt.Sprintf("это лишь начальное значение поля %s: дальше его перезаписывает %s", shortField(ow[0].Field), ow[0].Method)
		}
		add("field_overwritten", w, why)
	}
	if req.ServerDependency {
		add("server_dependency", -2.5, "заявлена серверная зависимость — локальный патч может быть перекрыт сервером")
	}

	// 5. Re-clamp / guard: a concrete clamp is decisive; a generic comparison is only a warning.
	switch {
	case eff != nil && *eff == req.Expected:
		add("clamp_cancels", -3.0, fmt.Sprintf("ограничитель возвращает значение к %d — патч ничего не меняет", *eff))
	case eff != nil && *eff != req.Replacement:
		add("clamp_partial", -1.5, fmt.Sprintf("ограничитель срежет %d до %d — эффект будет частичным", req.Replacement, *eff))
	case len(clamps) > 0:
		add("clamp_ok", 0.3, "ограничитель найден, но новое значение в его пределах")
	default:
		if clamped, why := reClamped(rr, req.Replacement); clamped {
			add("compared_later", -0.6, why)
		}
	}

	// 6. Change kind risk.
	switch kind {
	case "repoint", "change_sentinel":
		add("high_risk_kind", -1.3, "смена ID ресурса/маркера часто ломает тип или сравнение, а не даёт нужный эффект")
	case "change_mask", "change_color":
		add("opaque_kind", -0.4, "побитовый/цветовой эффект трудно подтвердить без запуска")
	case "enable", "raise_limit", "lower_duration", "raise_duration", "disable", "lower_limit":
		add("direct_kind", 0.6, "прямое числовое/логическое изменение с предсказуемым эффектом")
	}

	// 7. Mechanical soundness from the planner.
	switch {
	case perr != nil:
		add("not_mechanical", -2.0, "патч механически не строится (устаревший литерал, не тот opcode, регистр не влезает)")
	default:
		add("preflight_ok", 0.8, "литерал однозначно найден, opcode и регистр подобраны, частичный preflight пройден")
	}

	z := bias
	for _, x := range f {
		z += x.Weight
	}
	p := sigmoid(z)
	var caps []string
	if eff != nil && *eff == req.Expected && p > 0.05 {
		p = 0.05
		caps = append(caps, "ограничитель возвращает исходное значение — патч не меняет поведение → не выше 5%")
	} else if eff != nil && *eff != req.Replacement && p > 0.4 {
		p = 0.4
		caps = append(caps, "нужное значение не достигается из-за ограничителя → не выше 40%")
	}
	if len(ow) > 0 && ow[0].DefaultOnly && p > 0.45 {
		p = 0.45
		caps = append(caps, "патчится только начальное значение поля, которое перезаписывается в другом методе → не выше 45%")
	}
	if req.ServerDependency && p > 0.5 {
		p = 0.5
		caps = append(caps, "решение может приниматься на сервере — локальный патч не выше 50%")
	}
	if p > 0.9 {
		p = 0.9
		caps = append(caps, "без реальной сборки и теста выше 90% не поднимаем")
	}
	p = round2(p)
	band := "low"
	if p >= 0.75 {
		band = "high"
	} else if p >= 0.45 {
		band = "medium"
	}
	if eff != nil && *eff != req.Replacement && *eff != req.Expected {
		band = "partial"
	}
	return Success{
		Probability: p, Band: band, Factors: f, Caps: caps,
		Calibration: "структурная оценка из факторов, НЕ откалибрована на реальных исходах патчей; читайте факторы, а не только число. Подтверждают эффект только сборка, тест и человек.",
	}
}

// reClamped detects a later min/max comparison that would pull the value back toward the old range.
func reClamped(rr smalirole.Report, after int64) (bool, string) {
	for _, e := range rr.Evidence {
		for _, t := range e.Tags {
			t = strings.TrimPrefix(t, "callee:")
			if t == "cmp:order" {
				return true, fmt.Sprintf("значение сравнивается на «больше/меньше» (строка %d) — есть ограничитель, который может вернуть его в прежние рамки", e.Line)
			}
			if strings.Contains(t, "call:tok:min") || strings.Contains(t, "call:tok:max") || strings.Contains(t, "call:tok:coerce") || strings.Contains(t, "call:tok:clamp") {
				return true, fmt.Sprintf("значение проходит через clamp/min/max (строка %d) — итог может быть пересчитан", e.Line)
			}
		}
	}
	return false, ""
}

func effortEstimate(req Request, rr smalirole.Report, perr error, roleFromClamp, clampBlocks bool) Effort {
	var drivers []string
	score := 1.0
	bump := func(by float64, why string) { score += by; drivers = append(drivers, why) }

	interproc := false
	branches := 0
	for _, e := range rr.Evidence {
		if e.Via != "" {
			interproc = true
		}
		for _, t := range e.Tags {
			if strings.Contains(t, "cmp:") {
				branches++
			}
		}
	}
	if n := len(rr.Evidence); n == 0 {
		bump(1.5, "значение не используется — придётся искать настоящее место эффекта вручную")
	} else if n >= 4 {
		bump(1.0, fmt.Sprintf("значение расходится в %d мест — нужно проверить все", n))
	}
	if interproc {
		bump(1.0, "эффект уходит в другой метод — проверка межпроцедурная")
	}
	if branches >= 2 {
		bump(0.5, "значение участвует в нескольких ветвлениях")
	}
	if req.ServerDependency {
		bump(1.5, "серверная зависимость — нужен сервер/мок для проверки")
	}
	if rr.Abstained && !roleFromClamp {
		bump(1.0, "роль не ясна — сначала реверс, потом патч")
	}
	if clampBlocks {
		bump(1.5, "ограничитель срезает новое значение — нужна вторая правка (граница) и повторная проверка")
	} else if roleFromClamp {
		bump(0.5, "есть ограничитель — проверить, что новое значение в его пределах")
	}
	if perr != nil {
		bump(1.0, "механика рерайта требует более широкого изменения (opcode/регистр)")
	}
	if strings.Contains(req.Code, "const/high16") || rr.FloatValue != nil {
		bump(0.5, "значение float/high16 — другой тип правки")
	}

	level, lo, hi := "trivial", 2, 5
	switch {
	case score >= 4.5:
		level, lo, hi = "high", 60, 240
	case score >= 3:
		level, lo, hi = "medium", 20, 60
	case score >= 1.8:
		level, lo, hi = "low", 8, 20
	}
	if len(drivers) == 0 {
		drivers = append(drivers, "одиночный литерал, одно локальное использование")
	}
	return Effort{
		Level: level, MinMinutes: lo, MaxMinutes: hi, Drivers: drivers,
		Note: "ориентировочная сложность для разработчика (найти место, собрать, проверить тестом), а не гарантия по времени; реальная оценка зависит от проекта и окружения.",
	}
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func roleRU(r string) string {
	m := map[string]string{
		"bitmask": "битовая маска", "flag_bit": "флаг-бит", "sentinel": "значение-маркер",
		"color_argb": "цвет ARGB", "layout_param": "размер LayoutParams", "boolean": "булево значение",
		"limit_threshold": "порог/лимит", "counter_step": "шаг счётчика", "duration_ms": "длительность/таймаут",
		"resource_id": "ID ресурса", "index_or_size": "индекс/размер", "api_constant": "константа API",
	}
	if x, ok := m[r]; ok {
		return x
	}
	return "значение"
}
