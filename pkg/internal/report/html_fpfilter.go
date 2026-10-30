package report

import (
	"fmt"
	"html"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NEW SECTION: FP Filter Layer
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildFPFilterSection(sb htmlWriter, view HTMLReportView) {
	if r.result.FPFilterResults == nil {
		return
	}

	fp := r.result.FPFilterResults
	sb.WriteString(`<section class="section" id="fp-filter">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>False Positive & Noise Reduction Filter</span></h2>`, icon("filter")))
	sb.WriteString(`<p class="section-desc">Automated triaging of findings into confirmed risks and suppressed boilerplate SDK noise.</p>`)

	// Stats Row
	sb.WriteString(`<div class="fp-stats-grid">`)
	statsCards := []struct{ label, value, class string }{
		{"Total Checked", fmt.Sprintf("%d", fp.Stats.TotalFindings), ""},
		{"App Risks", fmt.Sprintf("%d", fp.Stats.ConfirmedAppRisks), "danger"},
		{"SDK Risks", fmt.Sprintf("%d", fp.Stats.ConfirmedSDKRisks), "warning"},
		{"SDK Interesting", fmt.Sprintf("%d", fp.Stats.SDKInteresting), "accent"},
		{"SDK Noise Suppressed", fmt.Sprintf("%d", fp.Stats.SuppressedSDKNoise), "success"},
		{"Generic Suppressed", fmt.Sprintf("%d", fp.Stats.GenericNoiseSuppressed), "success"},
	}

	for _, sc := range statsCards {
		sb.WriteString(fmt.Sprintf(`<div class="fp-stat-card %s">`, sc.class))
		sb.WriteString(fmt.Sprintf(`<div class="fp-stat-val">%s</div>`, sc.value))
		sb.WriteString(fmt.Sprintf(`<div class="fp-stat-label">%s</div>`, sc.label))
		sb.WriteString(`</div>`)
	}
	sb.WriteString(`</div>`)

	// Suppressed Findings Details (Collapsible)
	if len(fp.SuppressedFindings) > 0 {
		sb.WriteString(`<details class="fp-suppressed-details">`)
		sb.WriteString(fmt.Sprintf(`<summary>View Suppressed Noise Log (%d items)</summary>`, len(fp.SuppressedFindings)))
		sb.WriteString(`<div class="fp-log-content">`)

		for _, cf := range fp.SuppressedFindings {
			if cf.Original == nil {
				continue
			}
			sb.WriteString(`<div class="fp-log-item">`)
			sb.WriteString(fmt.Sprintf(`<span class="fp-log-cat">%s</span>`, html.EscapeString(string(cf.Original.Category))))
			sb.WriteString(fmt.Sprintf(`<span class="fp-log-pat"><code>%s</code></span>`, html.EscapeString(cf.Original.Pattern)))
			sb.WriteString(fmt.Sprintf(`<span class="fp-log-reason">%s</span>`, html.EscapeString(cf.SuppressionReason)))
			if cf.SDKInfo != nil {
				sb.WriteString(fmt.Sprintf(`<span class="fp-log-sdk">SDK: %s</span>`, html.EscapeString(cf.SDKInfo.Name)))
			}
			sb.WriteString(`</div>`)
		}

		if len(fp.SuppressedFindings) < fp.Stats.SuppressedSDKNoise+fp.Stats.GenericNoiseSuppressed {
			sb.WriteString(`<div class="fp-log-item fp-log-more">... and more (log truncated)</div>`)
		}
		sb.WriteString(`</div></details>`)
	}

	sb.WriteString(`</section>`)
}
