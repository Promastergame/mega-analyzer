package report

import (
	"fmt"
	"html"
)

func (r *HTMLReporter) buildDecisionAISection(w htmlWriter) {
	d := r.result.DecisionAI
	if d == nil {
		return
	}
	w.WriteString(`<section class="section" id="decision-ai"><h2 class="section-title">` + icon("cpu") + `<span>DecisionAI · Review assistant</span></h2>`)
	w.WriteString(`<style>#decision-ai .hotspot-card{overflow-wrap:anywhere}#decision-ai summary{cursor:pointer;line-height:1.6}#decision-ai summary span{font-weight:400;opacity:.8;margin-left:.5em}#decision-ai .hotspot-card p{margin-top:.75em}</style>`)
	w.WriteString(`<p class="section-desc">Additional review of scanner evidence. Original findings, severity and CI verdicts are preserved. Model scores have not been validated on your apps.</p>`)
	fmt.Fprintf(w, `<div class="card"><div class="hotspot-meta"><span>Status: %s</span><span>Reviewed: %d / %d</span><span>Skipped: %d</span></div></div>`, html.EscapeString(d.Status), d.Processed, d.Total, d.Skipped)
	if d.Error != "" {
		fmt.Fprintf(w, `<p class="section-desc">Service error: %s</p>`, html.EscapeString(d.Error))
	}
	w.WriteString(`<div class="hotspots-list">`)
	for _, e := range d.Entries {
		a := e.Response.Answers["false_positive"]
		kind := "Model recommendation"
		if e.AssessmentKind == "scanner_rule_advisory" {
			kind = "Scanner rules · not independent confirmation"
		}
		title := e.Title
		if title == "" {
			title = e.RuleID
		}
		fmt.Fprintf(w, `<details class="hotspot-card"><summary><strong>%s</strong> <span>%s · %s</span></summary><p>%s</p><p><code>%s</code></p>`, html.EscapeString(title), html.EscapeString(e.Severity), html.EscapeString(e.ReviewRoute), kind, html.EscapeString(e.RuleID))
		if a.Noul != nil {
			fmt.Fprintf(w, `<p>False-positive score: <strong>%.4f</strong></p>`, *a.Noul)
		}
		if a.Abstained {
			fmt.Fprintf(w, `<p>Insufficient evidence: %s</p>`, html.EscapeString(a.Reason))
		}
		if e.ContextTruncated {
			w.WriteString(`<p>Context was shortened to the input limit. Review the full source.</p>`)
		}
		for _, loc := range e.Locations {
			fmt.Fprintf(w, `<p><code>%s:%d</code></p>`, html.EscapeString(loc.File), loc.Line)
		}
		fmt.Fprintf(w, `<p>Source: %s · Version: %s · Model: %s</p>`, html.EscapeString(a.Source), html.EscapeString(e.Response.Version), html.EscapeString(e.Response.Model))
		for _, ev := range a.Evidence {
			fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(ev))
		}
		for _, check := range a.Checks {
			fmt.Fprintf(w, `<p><strong>Next check: %s</strong> — %s</p>`, html.EscapeString(check.Title), html.EscapeString(check.Why))
		}
		for _, warning := range e.Response.Warnings {
			fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(warning))
		}
		w.WriteString(`</details>`)
	}
	w.WriteString(`</div></section>`)
}
