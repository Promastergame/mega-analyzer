package textai

import (
	"decisionai/engine"
	"math"
	"strings"
)

// CheckGate only checks caller-supplied records. It does not authenticate or execute tests.
func CheckGate(r Request) Gate {
	g := Gate{Status: "blocked", Reasons: []string{}, ChecksSource: "caller_supplied_not_authenticated"}
	if r.CandidateCode == "" {
		g.Reasons = append(g.Reasons, "Нет candidate_code для сопоставления SHA-256.")
	} else {
		g.CandidateSHA256 = SHA256(r.CandidateCode)
		if v := engine.ValidateSmali(r.CandidateCode); v.Status == "fail" {
			g.Reasons = append(g.Reasons, "Кандидат не прошёл частичный Smali preflight.")
		}
	}
	c := r.Checks
	if c == nil {
		g.Reasons = append(g.Reasons, "Нет структурированных результатов checks. Текст state не заменяет проверки.")
		return g
	}
	if !c.AppOwned || c.Library {
		g.Reasons = append(g.Reasons, "Не подтверждена принадлежность к коду приложения.")
	}
	if c.Scope != "defensive" && c.Scope != "test_fixture" {
		g.Reasons = append(g.Reasons, "Scope не разрешает подготовку кандидата.")
	}
	if c.Build != "pass" {
		g.Reasons = append(g.Reasons, "Для текущего кандидата нет успешной сборки.")
	}
	if c.Runtime != "pass" || !c.EffectVerified {
		g.Reasons = append(g.Reasons, "Для текущего кандидата не подтверждён нужный эффект.")
	}
	if c.ServerDependency != "local_only" {
		g.Reasons = append(g.Reasons, "Не исключена серверная зависимость.")
	}
	if g.CandidateSHA256 == "" || strings.ToLower(c.TestedSHA256) != g.CandidateSHA256 {
		g.Reasons = append(g.Reasons, "tested_sha256 не совпадает с текущим кандидатом.")
	}
	if len(g.Reasons) == 0 {
		g.Status = "records_match"
		g.Reasons = append(g.Reasons, "Переданные записи проверок относятся к SHA-256 текущего кандидата; их подлинность этим модулем не проверена.")
	}
	return g
}

// reliabilityReasons explains why a model prediction is not eligible for a
// yes/no answer. It covers only lexical reliability (unknown vocabulary,
// truncated input). Uncertainty between thresholds is reported separately as
// confidence_below_threshold by the caller.
func reliabilityReasons(_ Request, p Prediction) []string {
	reasons := []string{}
	for _, f := range p.Fields {
		if f.Truncated {
			reasons = append(reasons, "truncated_input")
			break
		}
	}
	// Support includes half-credit for familiar subwords, but pure subword
	// similarity caps at 0.5, so unfamiliar text alone cannot pass 0.6.
	if p.Support < 0.6 {
		reasons = append(reasons, "low_lexical_support")
	}
	return reasons
}

func heuristic(r Request) Prediction {
	s := strings.ToLower(r.State)
	p := .5
	cs := []Contribution{}
	for _, item := range []struct {
		phrase string
		value  float64
	}{{"тест поведения прошёл", .25}, {"тесты прошли", .15}, {"build passed", .15}, {"effect confirmed", .2}, {"не выполнялись", -.35}, {"не запускались", -.35}, {"предыдущей версии", -.3}, {"тест завершился ошибкой", -.4}, {"runtime failed", -.4}, {"назначение неизвестно", -.25}, {"сервер", -.1}} {
		if strings.Contains(s, item.phrase) {
			p += item.value
			cs = append(cs, Contribution{"state contains: " + item.phrase, item.value})
		}
	}
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	return Prediction{Value: p, Kind: "heuristic_score", Coverage: 0, Support: 0, Entropy: entropy(p), Contributions: cs, Notes: []string{"Модель не загружена. Это лексическая эвристика, не вероятность.", "Свободные критерии не исполняются как правила и не понимаются универсально."}}
}
func modelSummary(m *Model) *ModelSummary {
	if m == nil {
		return nil
	}
	return &ModelSummary{Version: m.Version, FeatureSchema: m.FeatureSchema, Features: len(m.Vocabulary), Synthetic: m.Synthetic, Metrics: m.Metrics}
}

func Analyze(r Request, m *Model) (Report, error) {
	// A single task is supported, so an empty task_id defaults to it instead
	// of failing. A wrong non-empty task_id is still rejected by Validate.
	if r.TaskID == "" {
		r.TaskID = Task
	}
	if e := Validate(r); e != nil {
		return Report{}, e
	}
	if m != nil {
		if e := m.Validate(); e != nil {
			return Report{}, e
		}
	}
	t := .85
	if r.Threshold != nil {
		t = *r.Threshold
	}
	// Fix overlapping YES/NO zones at low thresholds: the effective threshold
	// is never below 0.5, so YES (p>=effective, p>0.5) and NO (p<=1-effective,
	// p<0.5) are disjoint. The requested threshold is preserved in Threshold.
	effective := math.Max(.5, t)
	p := heuristic(r)
	if m != nil {
		p = m.Predict(r)
	}
	out := Report{Version: Version, ID: r.ID, TaskID: r.TaskID, Answer: "unknown", Prediction: p, Threshold: t, EffectiveThreshold: effective, AboveThreshold: p.Value >= effective, Gate: CheckGate(r), Decision: "review", CanApply: false, Explanation: "Классификатор оценивает текст по обученным лексическим признакам; смысл и эффект патча не доказаны.", Warnings: []string{"Автоприменение отсутствует. checks принимаются от вызывающей стороны и должны формироваться доверенным сборщиком/тестами, не из текста файла."}, Model: modelSummary(m)}
	if m == nil {
		out.AbstentionReasons = []string{"model_not_loaded"}
	} else {
		reasons := reliabilityReasons(r, p)
		if len(reasons) == 0 {
			if p.Value > .5 && p.Value >= effective {
				out.Answer = "yes"
			} else if p.Value < .5 && p.Value <= 1-effective {
				out.Answer = "no"
			} else {
				out.AbstentionReasons = []string{"confidence_below_threshold"}
			}
		} else {
			out.AbstentionReasons = reasons
		}
	}
	if out.Gate.Status == "blocked" {
		out.Decision = "blocked"
	} else if m == nil {
		out.Decision = "review"
		out.Warnings = append(out.Warnings, "Без обученной модели нельзя выдавать модельное одобрение.")
	} else if m.Synthetic {
		out.Decision = "demo_only"
	} else if len(out.AbstentionReasons) > 0 && out.Answer == "unknown" && (p.Support < .6 || hasReason(out.AbstentionReasons, "truncated_input")) {
		out.Decision = "needs_context"
		out.Warnings = append(out.Warnings, "Слабое лексическое покрытие или усечённый вход: возможен выход за пределы обученной задачи.")
	} else if out.Answer == "yes" {
		out.Decision = "candidate_for_review"
	} else {
		out.Decision = "review"
	}
	for _, f := range p.Fields {
		if f.Truncated {
			out.Warnings = append(out.Warnings, "Вход усечён до 2048 токенов в поле: ответ учитывает только начало текста.")
			break
		}
	}
	if t <= .5 {
		out.Warnings = append(out.Warnings, "Threshold <=0.5: применён эффективный порог 0.5, зоны YES/NO разделены; для guardrail используйте более высокий порог.")
	}
	return out, nil
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
