package client

import (
	"context"
	"fmt"
	"strings"
)

// PatchRun is what a patch pipeline knows after building and testing one candidate.
// State() turns it into the fields DecisionAI's experts read, so callers never hand-write JSON.
type PatchRun struct {
	Method string // e.g. "Wallet.addCoins()"
	Code   string // Smali body of the method (enables the trained smalirole model)
	Line   int    // 1-based line of the patched const inside Code (0 = the only const)
	Before int64  // literal before the patch
	After  int64  // literal after the patch

	CandidateSHA256 string // hash of the candidate that is being judged
	TestedSHA256    string // hash of the build the tests actually ran on
	Build           string // pass | fail | not_run
	Runtime         string // pass | fail | not_run
	Device          string
	EffectVerified  *bool  // set by the behaviour test, not by a human note
	ServerDep       string // local_only | cache | server_validated | server_decides | "" (unknown)
	NetworkRequests *int   // requests observed during the test
	Notes           string // free-text observations
}

// Bool and Int are small helpers for the optional fields.
func Bool(b bool) *bool { return &b }
func Int(n int) *int    { return &n }

// State returns the request state for the patch questions.
func (p PatchRun) State() map[string]any {
	s := map[string]any{}
	if p.Method != "" {
		s["candidate"] = fmt.Sprintf("%s const 0x%x → 0x%x", p.Method, p.Before, p.After)
	}
	if strings.TrimSpace(p.Code) != "" {
		s["code"] = p.Code
		if p.Line > 0 {
			s["line"] = p.Line
		}
	}
	if p.Build != "" {
		b := map[string]any{"status": p.Build}
		if p.CandidateSHA256 != "" && p.TestedSHA256 != "" {
			b["sha256_matches"] = strings.EqualFold(p.CandidateSHA256, p.TestedSHA256)
		}
		s["build"] = b
	}
	if p.Runtime != "" {
		r := map[string]any{"status": p.Runtime}
		if p.Device != "" {
			r["device"] = p.Device
		}
		s["runtime"] = r
	}
	if p.EffectVerified != nil {
		s["effect_verified"] = *p.EffectVerified
	}
	if p.ServerDep != "" {
		s["server_dependency"] = p.ServerDep
	}
	if p.NetworkRequests != nil {
		s["network_requests"] = *p.NetworkRequests
	}
	if p.Notes != "" {
		s["notes"] = p.Notes
	}
	return s
}

// PatchQuestions are the three standard questions about a patched literal.
func PatchQuestions() map[string]Question {
	return map[string]Question{
		"effect_confirmed": ForTask("patch_effect", Noul("Подтверждён ли нужный эффект патча?",
			"Эффект наблюдался на текущей сборке", "Эффект не наблюдался, тест не запускался или был на другой версии")),
		"literal_role": ForTask("literal_role", Choice("Какую роль играет изменённый литерал?",
			Opt("limit", "Лимит или максимум значения"), Opt("delay", "Задержка или таймер"),
			Opt("color", "Цвет или элемент интерфейса"), Opt("resource_id", "Идентификатор ресурса"), Opt("other", ""))),
		"server_dependency": ForTask("server_dependency", Score("Насколько поведение зависит от сервера?",
			Opt("0", "Полностью локально"), Opt("1", "Есть кэш с сервера"), Opt("2", "Сервер проверяет значение"), Opt("3", "Значение решает сервер"))),
	}
}

// PatchVerdict is the typed result for one patch run.
type PatchVerdict struct {
	Effect, Role, Server Answer
	// Ready is true only when every answer was routed "auto", the effect is confirmed and
	// the behaviour is local. It is a recommendation; applying the patch stays the caller's decision.
	Ready   bool
	Reasons []string // why Ready is false
}

// DecidePatch asks the three patch questions for one run.
func (c *Client) DecidePatch(ctx context.Context, p PatchRun) (PatchVerdict, error) {
	resp, err := c.Decide(ctx, Request{State: p.State(), Questions: PatchQuestions()})
	if err != nil {
		return PatchVerdict{}, err
	}
	v := PatchVerdict{Effect: resp.Answers["effect_confirmed"], Role: resp.Answers["literal_role"], Server: resp.Answers["server_dependency"]}
	for _, x := range []struct {
		name string
		a    Answer
	}{{"effect_confirmed", v.Effect}, {"literal_role", v.Role}, {"server_dependency", v.Server}} {
		if x.a.Route != "auto" {
			v.Reasons = append(v.Reasons, fmt.Sprintf("%s: route %s", x.name, x.a.Route))
		}
	}
	if v.Effect.Noul < 0.5 {
		v.Reasons = append(v.Reasons, "effect not confirmed")
	}
	if v.Server.Probabilities["0"] < 0.5 {
		v.Reasons = append(v.Reasons, "behaviour may depend on the server")
	}
	v.Ready = len(v.Reasons) == 0
	return v, nil
}
