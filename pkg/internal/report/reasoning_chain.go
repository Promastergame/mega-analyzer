package report

// ═══════════════════════════════════════════════════════════════════════════════
// REASONING CHAIN — explainable, AI-style step-by-step logic for HOTSPOTS only.
//
// Every hotspot card in REPORT.html shows *why* the engine flagged the file:
// the trigger it saw, the worst-case hypothesis, corroboration, the
// counter-evidence that pulls the score down, the GNN cross-check, and the
// final calibrated verdict. Built entirely from data the analysis already
// produced — zero extra scan cost.
// ═══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ChainStepView is one node of a hotspot's reasoning chain.
type ChainStepView struct {
	Kind   string // trigger | hypothesis | support | counter | ml | verdict
	Title  string
	Detail string
	Tag    string // small badge, e.g. "signal 0.61", "abstain", "context"
}

func (b *ViewBuilder) buildReasoningChain(hs types.Hotspot) []ChainStepView {
	steps := make([]ChainStepView, 0, 6)
	conf := estimateConfidence(hs)

	// 1 · Trigger — the strongest concrete signal we actually saw.
	trigger := ""
	if len(hs.DecisionPoints) > 0 {
		best := hs.DecisionPoints[0]
		for _, dp := range hs.DecisionPoints {
			if dp.Confidence > best.Confidence {
				best = dp
			}
		}
		trigger = best.Description
		if trigger == "" {
			trigger = best.Method
		}
	}
	if trigger == "" && len(hs.Reasons) > 0 {
		trigger = hs.Reasons[0]
	}
	if trigger == "" {
		trigger = fmt.Sprintf("%d pattern match(es) concentrated in this file", hs.MatchCount)
	}
	steps = append(steps, ChainStepView{
		Kind: "trigger", Title: "Trigger",
		Detail: trigger,
		Tag:    fmt.Sprintf("signal %.2f", conf),
	})

	// 2 · Hypothesis — the worst-case reading, stated honestly.
	catInfo := types.GetCategoryInfo(mainCategory(hs))
	steps = append(steps, ChainStepView{
		Kind: "hypothesis", Title: "Hypothesis",
		Detail: hypothesisForGroup(catInfo.Group),
		Tag:    catInfo.Name,
	})

	// 3 · Corroboration — other signals in the same file.
	if hs.MatchCount > 1 {
		detail := fmt.Sprintf("%d matches in this file, %d tagged critical.", hs.MatchCount, hs.CriticalCount)
		if len(hs.Reasons) > 1 {
			detail += " Also: " + truncateString(strings.Join(hs.Reasons[1:], "; "), 160)
		}
		steps = append(steps, ChainStepView{
			Kind: "support", Title: "Corroboration",
			Detail: detail,
			Tag:    fmt.Sprintf("+%d", hs.MatchCount-1),
		})
	}

	// 4 · Counter-evidence — the calibrated detector's view of the whole app.
	piracyConf := 0.0
	if b.result.Piracy != nil {
		piracyConf = b.result.Piracy.Confidence
	}
	if piracyConf < 0.5 {
		steps = append(steps, ChainStepView{
			Kind: "counter", Title: "Counter-evidence",
			Detail: fmt.Sprintf("Piracy detector did not confirm a real bypass (calibrated confidence %.2f) — no crack watermark, repack signature or tamper marker backing this file.", piracyConf),
			Tag:    fmt.Sprintf("\u2212%.2f", 0.5-piracyConf),
		})
	} else if hs.CriticalCount == 0 {
		steps = append(steps, ChainStepView{
			Kind: "counter", Title: "Counter-evidence",
			Detail: "No critical-strength evidence inside this specific file; the concentration alone is not proof.",
			Tag:    "weak",
		})
	}

	// 5 · GNN cross-check — per-file when available, else global abstention.
	gnnDetail := "Graph model produced no accepted finding for this file — no ML support for a real vulnerability."
	gnnTag := "abstain"
	for _, gf := range b.result.GNNFindings {
		// Dummy-weight findings never confirm anything: a random network's
		// output must not upgrade a verdict.
		if gf.Dummy {
			continue
		}
		if gf.FilePath != "" && gf.FilePath == hs.Path {
			gnnDetail = fmt.Sprintf("Graph model flags %s in %s (p=%.2f).", gf.VulnClass, gf.Method, gf.Confidence)
			gnnTag = "confirm"
			break
		}
	}
	steps = append(steps, ChainStepView{
		Kind: "ml", Title: "GNN cross-check",
		Detail: gnnDetail,
		Tag:    gnnTag,
	})

	// 6 · Verdict — calibrated, honest.
	verdict := "Low-signal; kept for triage context, should not drive the global risk on its own."
	tag := "context"
	switch {
	case conf >= 0.7 && hs.CriticalCount > 0 && gnnTag == "confirm":
		verdict = "Multiple independent signals and the ML model agree — prioritize manual review of this file."
		tag = "priority"
	case conf >= 0.7 && hs.CriticalCount > 0:
		verdict = "Strong rule-based evidence without ML confirmation — review manually before trusting the score."
		tag = "review"
	case conf >= 0.45:
		verdict = "Ambiguous — worth a manual look, but not proof of piracy by itself."
		tag = "manual"
	}
	steps = append(steps, ChainStepView{
		Kind: "verdict", Title: "Verdict",
		Detail: verdict,
		Tag:    tag,
	})

	return steps
}

// hypothesisForGroup states the worst-case interpretation for a category group.
func hypothesisForGroup(group string) string {
	switch strings.ToLower(group) {
	case "piracy":
		return "Could be a crack watermark, repack trace or piracy-site reference."
	case "network":
		return "Could be a license phone-home or trial/expiry gate (time check + remote endpoint)."
	case "premium", "subscription", "trial", "license":
		return "Could be a paywall / license gate that a crack would target or neutralize."
	case "security":
		return "Could be tamper-detection or anti-debug logic that was modified or bypassed."
	case "technical":
		return "Could be obfuscation or reflection hiding a tampered check."
	default:
		return "Could be supporting infrastructure for a license check or its bypass."
	}
}
