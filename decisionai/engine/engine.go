package engine

import (
	"fmt"
	"strings"
)

func ValidateRequest(r Request) error {
	if len(r.Code) == 0 || len(r.Code) > 1024*1024 {
		return fmt.Errorf("code must be 1..1048576 bytes")
	}
	if len(r.Questions) > 100 || len(r.Meta.Evidence) > 128 {
		return fmt.Errorf("questions/evidence limit exceeded")
	}
	if len(r.ID) > 256 {
		return fmt.Errorf("id too long")
	}
	switch r.Scope {
	case "", "audit", "defensive", "test_fixture":
	default:
		return fmt.Errorf("unsupported scope")
	}
	if r.Threshold != nil {
		for _, v := range []float64{r.Threshold.Finding, r.Threshold.Patch} {
			if !finite(v) || v < 0 || v > 1 {
				return fmt.Errorf("threshold must be in [0,1]")
			}
		}
	}
	for _, q := range r.Questions {
		if strings.TrimSpace(q.Text) == "" || len(q.TrueWhen)+len(q.FalseWhen) > 64 {
			return fmt.Errorf("invalid question")
		}
		for _, cs := range [][]Condition{q.TrueWhen, q.FalseWhen} {
			for _, c := range cs {
				if err := validateCondition(c); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func Analyze(r Request, finding, patch *Model) (Report, error) {
	if err := ValidateRequest(r); err != nil {
		return Report{}, err
	}
	for _, item := range []struct {
		m      *Model
		target string
	}{{finding, "finding"}, {patch, "patch"}} {
		if item.m != nil {
			if err := item.m.Validate(); err != nil {
				return Report{}, err
			}
			if item.m.Target != item.target {
				return Report{}, fmt.Errorf("wrong model target")
			}
		}
	}
	t := DefaultThresholds()
	if r.Threshold != nil {
		t = *r.Threshold
	}
	f := Features(r)
	out := Report{Version: Version, ID: r.ID, Features: f, Answers: []Answer{}, Validation: ValidateSmali(r.Code), Finding: assess(f, "finding", t.Finding, finding), PatchAssessment: assess(f, "patch", t.Patch, patch), Decision: "review", Reasons: []string{"Автоприменение отключено. Сборка и поведение здесь не выполняются.", "Preflight — частичная проверка, не полный Smali/Dalvik verifier."}}
	if !out.Finding.AboveThreshold {
		out.Decision = "low_priority"
		out.Reasons = append(out.Reasons, "Находка ниже Threshold; сохранена, а не скрыта.")
	}
	for _, q := range r.Questions {
		a := AnswerQuestion(r.State, q)
		out.Answers = append(out.Answers, a)
		if a.State == "conflict" {
			out.Decision = "blocked"
			out.Reasons = append(out.Reasons, "true_when и false_when одновременно выполнены.")
		} else if a.State == "unknown" && out.Decision != "blocked" {
			out.Decision = "needs_context"
		}
	}
	if out.Validation.Status == "fail" {
		out.Decision = "blocked"
		out.Reasons = append(out.Reasons, "Исходный код не прошёл частичную проверку.")
	}
	if r.Patch != nil {
		if !r.Meta.AppOwned || r.Meta.Library || (r.Scope != "defensive" && r.Scope != "test_fixture") {
			out.Decision = "blocked"
			out.Reasons = append(out.Reasons, "План требует app_owned, не-library и scope defensive/test_fixture.")
		} else if out.Decision != "blocked" {
			plan, e := PlanPatch(r.Code, *r.Patch)
			if PatchAdvisor != nil {
				if adv, ae := PatchAdvisor(r); ae == nil && adv != nil {
					out.Advice = adv
					if e != nil && adv.Plan != nil {
						plan, e = adv.Plan, nil
					}
				} else if ae != nil {
					out.Reasons = append(out.Reasons, "Анализ назначения константы недоступен: "+ae.Error())
				}
			}
			if e != nil {
				out.Decision = "blocked"
				out.Reasons = append(out.Reasons, e.Error())
			} else {
				out.Plan = plan
				if plan.Validation.Status == "fail" {
					out.Decision = "blocked"
				} else if out.Decision != "needs_context" {
					if out.PatchAssessment.AboveThreshold {
						out.Decision = "candidate_for_review"
					} else {
						out.Decision = "review"
						out.Reasons = append(out.Reasons, "Кандидат ниже patch Threshold; не одобрен автоматически.")
					}
				}
				if a := out.Advice; a != nil {
					plan.Explanation = a.WhatItDoes
					if r.Patch.Target != "" {
						plan.Explanation += " Заявленная цель: " + r.Patch.Target + " — сверьте с ролью выше."
					}
					if out.Decision != "blocked" {
						out.Decision = stricter(out.Decision, a.Verdict)
					}
					out.Reasons = append(out.Reasons, a.Reasons...)
				}
				if r.Meta.ServerDependency {
					out.Reasons = append(out.Reasons, "Есть заявленная серверная зависимость; локальный эффект не подтверждён.")
				}
			}
		}
	}
	return out, nil
}
