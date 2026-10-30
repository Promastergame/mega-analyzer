package ml

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CHAIN TRACE — структурированный аудит-след решений пайплайна
// ═══════════════════════════════════════════════════════════════════════════════
//
// Когда вызывающий код явно включает трассировку, каждый шаг пайплайна записывает
// структурированный след: ЧТО нашёл → ПОЧЕМУ такой скор → КАКУЮ стратегию выбрал
// → КАКОЙ результат сгенерировал → КАК он прошёл валидацию и строгий линт.
//
// Это НЕ «сырые рассуждения модели», а детерминированный аудит-лог решений
// движка: его можно приложить к отчёту, чтобы заказчик видел полную цепочку
// «сигнал → решение → патч → доказательство валидности».

// ChainStage — одна стадия цепочки.
type ChainStage struct {
	Name     string            `json:"name"`              // detect | signals | score | strategy | patch | validate | lint
	Started  time.Time         `json:"started"`           // метка начала стадии
	Duration time.Duration     `json:"duration"`          // сколько заняла стадия
	Summary  string            `json:"summary"`           // человекочитаемый итог стадии
	Details  map[string]string `json:"details,omitempty"` // ключевые факты (evidence, scores, opcodes)
}

// ChainTracer собирает стадии цепочки. Нулевое значение (nil) — no-op:
// все методы безопасны на nil-трейсере, поэтому вызовы можно расставлять
// в горячих путях без проверок и без оверхеда, когда флаг выключен.
type ChainTracer struct {
	Enabled bool         `json:"enabled"`
	Stages  []ChainStage `json:"stages"`

	cur *ChainStage
}

// NewChainTracer создаёт трейсер. enabled=false → все вызовы no-op.
func NewChainTracer(enabled bool) *ChainTracer {
	if !enabled {
		return nil
	}
	return &ChainTracer{Enabled: true, Stages: make([]ChainStage, 0, 8)}
}

// Begin открывает стадию.
func (ct *ChainTracer) Begin(name string) {
	if ct == nil {
		return
	}
	ct.Stages = append(ct.Stages, ChainStage{
		Name:    name,
		Started: time.Now(),
		Details: make(map[string]string),
	})
	ct.cur = &ct.Stages[len(ct.Stages)-1]
}

// Detail добавляет факт в текущую стадию.
func (ct *ChainTracer) Detail(key, value string) {
	if ct == nil || ct.cur == nil {
		return
	}
	ct.cur.Details[key] = value
}

// End закрывает текущую стадию с итогом.
func (ct *ChainTracer) End(summary string) {
	if ct == nil || ct.cur == nil {
		return
	}
	ct.cur.Summary = summary
	ct.cur.Duration = time.Since(ct.cur.Started)
	ct.cur = nil
}

// Render отдаёт человекочитаемую цепочку для отчёта/CLI.
func (ct *ChainTracer) Render() string {
	if ct == nil || len(ct.Stages) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("═══ CHAIN-ML-PATCH TRACE ═══\n")
	for i, s := range ct.Stages {
		fmt.Fprintf(&b, "%d. [%s] %s (%s)\n", i+1, s.Name, s.Summary, s.Duration.Round(time.Microsecond))
		keys := make([]string, 0, len(s.Details))
		for key := range s.Details {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(&b, "     %s: %s\n", key, s.Details[key])
		}
	}
	return b.String()
}

// ChainResult — результат полного прогона цепочки.
type ChainResult struct {
	Signals    *VulnerabilitySignals `json:"signals,omitempty"`
	Patch      string                `json:"patch,omitempty"`
	Validation ValidationResult      `json:"validation"`
	LintIssues []string              `json:"lint_issues,omitempty"`
	Trace      string                `json:"trace"` // Render() трейсера; пусто, если флаг выключен
}

// RunChainMLPatch — цепочка «детект → безопасное решение → доказательство».
//
//  1. detect/signals — AnalyzeVulnerabilitySignals по методу;
//  2. safety — чувствительные проверки доступа, лицензии и монетизации остаются
//     только диагностическими и не получают автоматический патч;
//  3. strategy/patch — генерация допустима лишь для остальных сигналов;
//  4. validate — SmaliValidator.ValidateStrict (regex + строгий линт).
//
// При chainMLPatch=true каждый шаг попадает в трейс (флаг «chain-ml-patch»).
func RunChainMLPatch(mi *MethodInfo, header, signature string, chainMLPatch bool) *ChainResult {
	ct := NewChainTracer(chainMLPatch)
	res := &ChainResult{}

	ct.Begin("signals")
	res.Signals = AnalyzeVulnerabilitySignals(mi)
	if res.Signals != nil {
		ct.Detail("count", fmt.Sprintf("%d", len(res.Signals.Signals)))
		for _, s := range res.Signals.Signals {
			ct.Detail(string(s.Kind), fmt.Sprintf("%s/%.2f", s.Severity, s.Confidence))
		}
		ct.End(fmt.Sprintf("%d signals detected", len(res.Signals.Signals)))
	} else {
		ct.End("no signals - no patch needed")
		res.Trace = ct.Render()
		return res
	}

	if allowed, reason := safeChainPatchDecision(res.Signals); !allowed {
		ct.Begin("safety")
		ct.Detail("decision", "diagnostic_only")
		ct.Detail("reason", reason)
		ct.End("automatic patch blocked by safety policy")
		res.Trace = ct.Render()
		return res
	}

	ct.Begin("strategy")
	kind := kindDefault
	chosen := "default"
	for _, s := range res.Signals.Signals {
		switch s.Kind {
		case VulnClientSideCurrency:
			kind, chosen = kindMaxInt, "currency->maxInt (more coins)"
		case VulnPremiumClientGate, VulnLicenseCheckClient:
			kind, chosen = kindTrue, "premium/license->true (unlock)"
		}
	}
	if mi != nil && mi.ReturnsVoid {
		kind, chosen = kindVoid, "void->swallow (swallow the check)"
	}
	ct.Detail("strategy", chosen)
	ct.End("strategy: " + chosen)

	ct.Begin("patch")
	rt := ""
	if mi != nil {
		rt = mi.ReturnType
	}
	res.Patch = buildStubMethodSmart(header, signature, rt, kind)
	ct.Detail("bytes", fmt.Sprintf("%d", len(res.Patch)))
	ct.End("patch generated")

	ct.Begin("validate")
	sv := NewSmaliValidator()
	res.Validation = sv.ValidateStrict(res.Patch)
	ct.Detail("valid", fmt.Sprintf("%v", res.Validation.Valid))
	ct.End(fmt.Sprintf("validation: valid=%v, errors=%d", res.Validation.Valid, len(res.Validation.Errors)))

	ct.Begin("lint")
	res.LintIssues = LintSmaliStrict(res.Patch)
	ct.Detail("issues", fmt.Sprintf("%d", len(res.LintIssues)))
	ct.End(fmt.Sprintf("strict lint: %d issues", len(res.LintIssues)))

	res.Trace = ct.Render()
	return res
}

// safeChainPatchDecision keeps high-risk authorization, licensing and
// monetization findings diagnostic-only. The analyzer may report the evidence
// and remediation guidance, but it must not synthesize an automatic bypass.
func safeChainPatchDecision(signals *VulnerabilitySignals) (bool, string) {
	if signals == nil {
		return false, "missing_signals"
	}
	for _, signal := range signals.Signals {
		switch signal.Kind {
		case VulnClientSideCurrency,
			VulnPremiumClientGate,
			VulnLicenseCheckClient,
			VulnAuthCheckBypass,
			VulnAgeVerification,
			VulnPremiumFeatureGate,
			VulnTrialPeriodCheck,
			VulnLicenseLocalOnly,
			VulnBiometricLocalOnly,
			VulnPaymentClientSide:
			return false, "access_license_or_monetization"
		}
	}
	return true, ""
}
