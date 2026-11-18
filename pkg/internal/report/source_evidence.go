package report

import (
	"fmt"
	"html"
	"io"
	"strings"
)

func (r *HTMLReporter) buildSourceEvidenceSection(w htmlWriter) {
	d := r.result.SourceEvidence
	if d == nil {
		return
	}
	w.WriteString(`<section class="section" id="source-evidence"><h2 class="section-title">` + icon("code") + `<span>Static source evidence</span></h2>`)
	w.WriteString(`<p class="section-desc">Cited checks of retained code and manifest declarations. Branch feasibility, hidden implementations and runtime behavior remain unresolved.</p>`)
	fmt.Fprintf(w, `<div class="card"><div class="hotspot-meta"><span>Status: %s</span><span>Methods available: %d / %d</span><span>Checks: %d</span><span>Omitted by limits: %d</span></div><p><a href="SOURCE_EVIDENCE.txt">Source details</a> · <a href="SOURCE_EVIDENCE.json">Source snapshots and SHA-256</a></p></div>`,
		html.EscapeString(d.Status), d.MethodsAnalyzed, d.MethodsDiscovered, len(d.Checks), d.ChecksOmitted)
	w.WriteString(`<div class="hotspots-list">`)
	for _, check := range d.Checks {
		fmt.Fprintf(w, `<details class="hotspot-card"><summary><strong>%s</strong> · %s · %s</summary><p>%s</p>`,
			html.EscapeString(check.Kind), html.EscapeString(check.Status), html.EscapeString(check.Choice), html.EscapeString(check.Summary))
		if check.Reason != "" {
			fmt.Fprintf(w, `<p>Remaining condition: %s</p>`, html.EscapeString(check.Reason))
		}
		for _, c := range check.Citations {
			fmt.Fprintf(w, `<p><code>%s:%d</code></p><pre>%s</pre>`, html.EscapeString(c.File), c.Line, html.EscapeString(c.Snippet))
		}
		w.WriteString(`</details>`)
	}
	w.WriteString(`</div></section>`)
}

func (r *MarkdownReporter) writeEvidenceDiagnostics(w io.Writer) error {
	if r.result == nil {
		return nil
	}
	var b strings.Builder
	if d := r.result.SourceEvidence; d != nil {
		fmt.Fprintf(&b, "\n## Static source evidence\n\nStatus: %s. Methods available: %d/%d. Checks: %d; omitted: %d.\n\n", d.Status, d.MethodsAnalyzed, d.MethodsDiscovered, len(d.Checks), d.ChecksOmitted)
		b.WriteString("Cited checks of retained code. Branch feasibility, hidden code and runtime behavior remain unresolved.\n\n")
		b.WriteString("| Check | Source assessment | Status |\n| --- | --- | --- |\n")
		for _, check := range d.Checks {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", evidenceMDCell(check.Kind), evidenceMDCell(check.Choice), evidenceMDCell(check.Status))
		}
		b.WriteString("\nSource details: [SOURCE_EVIDENCE.txt](SOURCE_EVIDENCE.txt) and [SOURCE_EVIDENCE.json](SOURCE_EVIDENCE.json).\n")
	}
	if d := r.result.GNNDiagnostics; d != nil {
		fmt.Fprintf(&b, "\n## GNN coverage\n\nStatus: %s. Visible methods: %d. Inferred: %d; skipped: %d; failed: %d; not processed: %d.\n\n",
			d.Status, d.MethodsDiscovered, d.MethodsInferred, d.MethodsSkipped, d.MethodsFailed, d.MethodsNotProcessed)
		b.WriteString("Model scope: licensing and protection patterns in retained method graphs. Hidden code and malware-family behavior remain unresolved.\n\n")
		fmt.Fprintf(&b, "Model: %s. SHA-256: %s. Calibration metadata present: %v.\n\n", evidenceMDCell(d.Model.TrainerVersion), evidenceMDCell(d.Model.SHA256), d.Model.HasCalibrationMetadata)
		b.WriteString("| Class | Method predictions |\n| --- | ---: |\n")
		for _, class := range d.Model.Taxonomy {
			fmt.Fprintf(&b, "| %s | %d |\n", evidenceMDCell(class), d.PredictionsByClass[class])
		}
		b.WriteString("\nFull predictions and skip reasons: [GNN_DIAGNOSTICS.json](GNN_DIAGNOSTICS.json).\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func evidenceMDCell(s string) string {
	return strings.NewReplacer("|", "\\|", "\r", " ", "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
}
