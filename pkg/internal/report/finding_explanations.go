package report

import (
	"encoding/hex"
	"fmt"
	"html"
	"strings"
	"unicode/utf8"
)

func explanationPreview(text string) string {
	binary := !utf8.ValidString(text)
	if !binary {
		for _, r := range text {
			if (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
				binary = true
				break
			}
		}
	}
	if binary {
		const byteLimit = 256
		preview := fmt.Sprintf("Binary evidence (%d bytes), hexadecimal preview:\n%s", len(text), hex.Dump([]byte(text[:min(len(text), byteLimit)])))
		if len(text) > byteLimit {
			preview += "[preview shortened; inspect the original artifact for complete bytes]"
		}
		return preview
	}
	const limit = 4096
	if len(text) <= limit {
		return text
	}
	n := limit
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n] + "\n[preview shortened; complete evidence in analysis.json]"
}

func (r *HTMLReporter) buildFindingExplanations(sb htmlWriter, items []TypedFindingView) {
	if len(items) == 0 && (r.result == nil || r.result.DecisionAI == nil && r.result.SourceEvidence == nil && r.result.GNNDiagnostics == nil) {
		return
	}
	reviews := r.findingReviews(items)
	sb.WriteString(`<section class="section" id="finding-explanations"><h2 class="section-title">Finding explanations</h2><p class="section-desc">Open a finding to inspect the source evidence, assumptions and remaining checks. An observation or heuristic is not proof of execution.</p>`)
	sb.WriteString(`<style>#finding-explanations .detail-card{margin:.75rem 0;padding:1rem;border:1px solid var(--border-default);border-radius:var(--radius-md);overflow-wrap:anywhere}#finding-explanations summary{cursor:pointer;line-height:1.6}#finding-explanations pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:28rem;overflow:auto}#finding-explanations p,#finding-explanations ul{margin:.75rem 0}</style>`)
	sb.WriteString(`<style>#finding-explanations .finding-review{border-top:1px solid var(--border-default);margin-top:1rem;padding-top:.75rem}#finding-explanations .analysis-coverage{margin:1rem 0;padding:.75rem 1rem;border:1px solid var(--border-default);border-radius:var(--radius-md)}#finding-explanations .review-origin{font-size:.85rem;color:var(--text-secondary);font-weight:600}#finding-explanations .review-item{padding:.5rem 0;overflow-wrap:anywhere}</style>`)
	r.buildFindingCoverage(sb, reviews)
	risks, observations := splitTypedFindings(items)
	r.buildFindingExplanationRows(sb, risks, reviews)
	if len(observations) > 0 {
		fmt.Fprintf(sb, `<details id="finding-observations"><summary>Capabilities and protections (%d observations)</summary><p>API references, permissions and protection checks are retained here. Their labels do not establish malicious use and do not increase the application risk score.</p>`, len(observations))
		r.buildFindingExplanationRows(sb, observations, reviews)
		sb.WriteString(`</details>`)
	}
	sb.WriteString(`</section>`)
}

func (r *HTMLReporter) buildFindingExplanationRows(sb htmlWriter, items []TypedFindingView, reviews findingReviewIndex) {
	for i, item := range items {
		if i >= 200 {
			sb.WriteString(`<p>Additional findings and full evidence are available in analysis.json.</p>`)
			break
		}
		fmt.Fprintf(sb, `<details class="detail-card" data-finding-id="%s"><summary>`, html.EscapeString(item.ID))
		fmt.Fprintf(sb, "<strong>%s · %s</strong> <code>%s</code></summary>", html.EscapeString(strings.ToUpper(item.Severity)), html.EscapeString(item.Title), html.EscapeString(item.RuleID))
		if ex := item.Explanation; ex != nil {
			fmt.Fprintf(sb, "<p><strong>Scanner assessment: %s</strong></p><p>%s</p>", html.EscapeString(ex.Status), html.EscapeString(explanationPreview(ex.Summary)))
			for _, list := range []struct {
				name   string
				values []string
			}{{"Matched conditions", ex.Conditions}, {"Limits", ex.Limitations}, {"Next checks", ex.NextChecks}} {
				if len(list.values) == 0 {
					continue
				}
				fmt.Fprintf(sb, "<p><strong>%s</strong></p><ul>", list.name)
				for _, value := range list.values {
					fmt.Fprintf(sb, "<li>%s</li>", html.EscapeString(explanationPreview(value)))
				}
				sb.WriteString(`</ul>`)
			}
		} else {
			fmt.Fprintf(sb, "<p>%s</p>", html.EscapeString(explanationPreview(item.Description)))
		}
		for j, evidence := range item.EvidenceItems {
			if j >= 16 {
				sb.WriteString(`<p>Further evidence is available in analysis.json.</p>`)
				break
			}
			fmt.Fprintf(sb, "<p><strong>%s</strong> · <code>%s:%d</code></p><pre><code>%s</code></pre>", html.EscapeString(explanationPreview(evidence.Description)), html.EscapeString(evidence.Location.File), evidence.Location.Line, html.EscapeString(explanationPreview(evidence.Snippet)))
		}
		r.buildFindingReviews(sb, reviews.items[findingReviewKey(item)])
		sb.WriteString(`</details>`)
	}
}

func (r *MarkdownRenderer) renderFindingExplanations(items []TypedFindingView) {
	if len(items) == 0 {
		return
	}
	r.sb.WriteString("## Finding explanations\n\nOpen a finding to inspect what matched and what still requires checking. Full evidence is retained in analysis.json.\n\n")
	risks, observations := splitTypedFindings(items)
	r.renderFindingExplanationRows(risks)
	if len(observations) > 0 {
		fmt.Fprintf(r.sb, "<details>\n<summary>Capabilities and protections (%d observations)</summary>\n\n", len(observations))
		r.renderFindingExplanationRows(observations)
		r.sb.WriteString("</details>\n\n")
	}
}

func (r *MarkdownRenderer) renderFindingExplanationRows(items []TypedFindingView) {
	for i, item := range items {
		if i >= 200 {
			break
		}
		fmt.Fprintf(r.sb, "<details>\n<summary>%s · %s</summary>\n\n", html.EscapeString(strings.ToUpper(item.Severity)), html.EscapeString(item.Title))
		fmt.Fprintf(r.sb, "Rule: `%s`\n\n", mdCell(item.RuleID))
		if ex := item.Explanation; ex != nil {
			fmt.Fprintf(r.sb, "Assessment: **%s**\n\n%s\n\n", mdCell(ex.Status), html.EscapeString(explanationPreview(ex.Summary)))
			for _, list := range []struct {
				name   string
				values []string
			}{{"Matched conditions", ex.Conditions}, {"Limits", ex.Limitations}, {"Next checks", ex.NextChecks}} {
				if len(list.values) == 0 {
					continue
				}
				fmt.Fprintf(r.sb, "**%s**\n\n", list.name)
				for _, value := range list.values {
					fmt.Fprintf(r.sb, "- %s\n", html.EscapeString(explanationPreview(value)))
				}
				r.sb.WriteString("\n")
			}
		}
		for j, evidence := range item.EvidenceItems {
			if j >= 16 {
				break
			}
			fmt.Fprintf(r.sb, "%s — `%s:%d`\n\n<pre>%s</pre>\n\n", html.EscapeString(explanationPreview(evidence.Description)), mdCell(evidence.Location.File), evidence.Location.Line, html.EscapeString(explanationPreview(evidence.Snippet)))
		}
		r.sb.WriteString("</details>\n\n")
	}
}
