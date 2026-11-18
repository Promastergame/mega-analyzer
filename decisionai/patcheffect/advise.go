package patcheffect

import (
	"fmt"

	"decisionai/engine"
	"decisionai/smalirole"
)

// Advisor returns an engine.PatchAdvisor backed by the role model (may be nil = expert rules)
// and optional app-wide context (nil = the method alone).
func Advisor(model *smalirole.Model, ctx func(code string) *smalirole.Ctx) func(engine.Request) (*engine.PatchAdvice, error) {
	return func(r engine.Request) (*engine.PatchAdvice, error) {
		if r.Patch == nil {
			return nil, nil
		}
		var c *smalirole.Ctx
		if ctx != nil {
			c = ctx(r.Code)
		}
		rep, err := AnalyzeCtx(Request{Code: r.Code, Line: r.Patch.Line, Expected: r.Patch.Expected, Replacement: r.Patch.Replacement,
			Target: r.Patch.Target, ServerDependency: r.Meta.ServerDependency, AppOwned: r.Meta.AppOwned, Library: r.Meta.Library}, model, c)
		if err != nil {
			return nil, err
		}
		return ToAdvice(r.Patch.Expected, r.Patch.Replacement, rep), nil
	}
}

// ToAdvice condenses a Report into the engine's verdict. Only strong, explainable evidence blocks.
func ToAdvice(before, after int64, rep Report) *engine.PatchAdvice {
	rr := rep.Role
	a := &engine.PatchAdvice{Role: rr.Answer, RoleConfidence: rr.Confidence, WhatItDoes: rep.WhatItDoes, ChangeKind: rep.ChangeKind,
		EffectiveValue: rep.Effective, SuccessProbability: rep.Success.Probability, SuccessBand: rep.Success.Band,
		EffortLevel: rep.Effort.Level, EffortMinutes: [2]int{rep.Effort.MinMinutes, rep.Effort.MaxMinutes}, Verdict: "ok", Plan: rep.Plan}
	if rr.Abstained {
		a.Role = "unknown"
	}
	set := func(v, why string) {
		a.Reasons = append(a.Reasons, why)
		if map[string]int{"ok": 0, "review": 1, "needs_context": 2, "blocked": 3}[v] > map[string]int{"ok": 0, "review": 1, "needs_context": 2, "blocked": 3}[a.Verdict] {
			a.Verdict = v
		}
	}
	switch {
	case rr.FloatValue != nil:
		set("blocked", fmt.Sprintf("Литерал — float %gf; целочисленная замена даст бессмысленное значение.", *rr.FloatValue))
	case rep.Effective != nil && *rep.Effective == before:
		set("blocked", fmt.Sprintf("Ограничитель дальше по коду возвращает значение к %d — патч ничего не меняет.", before))
	case rep.Effective != nil && *rep.Effective != after:
		set("review", fmt.Sprintf("Ограничитель срезает значение до %d вместо %d.", *rep.Effective, after))
	}
	if n := len(rep.Overwrites); n > 0 {
		o := rep.Overwrites[0]
		set("review", fmt.Sprintf("Поле %s перезаписывается в других местах (%d; первое: %s, «%s») — патч этой строки может быть затёрт.", shortField(o.Field), n, o.Method, o.Text))
	}
	if len(rr.Evidence) == 0 && rr.FloatValue == nil {
		set("blocked", "Значение не читается в методе — патч не влияет на поведение.")
	}
	if rr.Abstained && rep.Effective == nil && rr.FloatValue == nil {
		set("review", fmt.Sprintf("Роль константы не установлена (уверенность %.0f%%) — эффект патча неизвестен.", 100*rr.Confidence))
	}
	switch rep.ChangeKind {
	case "repoint", "change_sentinel":
		set("review", "Смена ресурса/API-константы/маркера — высокий риск поломки.")
	}
	if rep.Success.Band == "low" {
		set("review", fmt.Sprintf("Оценка успеха низкая (%.0f%%, эвристика).", 100*rep.Success.Probability))
	}
	a.Reasons = append(a.Reasons, fmt.Sprintf("Роль: %s (%.0f%%); шанс эффекта ≈%.0f%% (%s, эвристика, не калибровано на реальных патчах); трудозатраты: %s, %d–%d мин.",
		a.Role, 100*rr.Confidence, 100*rep.Success.Probability, rep.Success.Band, rep.Effort.Level, rep.Effort.MinMinutes, rep.Effort.MaxMinutes))
	return a
}
