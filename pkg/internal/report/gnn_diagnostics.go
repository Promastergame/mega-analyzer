package report

import (
	"fmt"
	"html"
	"strings"
)

func (r *HTMLReporter) buildGNNDiagnosticsSection(w htmlWriter) {
	d := r.result.GNNDiagnostics
	if d == nil {
		return
	}
	w.WriteString(`<section class="section" id="gnn-coverage"><h2 class="section-title">` + icon("cpu") + `<span>GNN coverage</span></h2>`)
	w.WriteString(`<p class="section-desc">Model scope: licensing and protection patterns in retained method graphs. Hidden code and malware-family behavior remain unresolved.</p>`)
	fmt.Fprintf(w, `<div class="card"><div class="hotspot-meta"><span>Status: %s</span><span>Visible methods: %d</span><span>Inferred: %d</span><span>Skipped: %d</span><span>Failed: %d</span><span>Not processed: %d</span></div>`,
		html.EscapeString(d.Status), d.MethodsDiscovered, d.MethodsInferred, d.MethodsSkipped, d.MethodsFailed, d.MethodsNotProcessed)
	fmt.Fprintf(w, `<p>Model: %s · Calibration metadata present: %v</p><p><code>%s</code></p><p>Classes: %s</p>`,
		html.EscapeString(d.Model.TrainerVersion), d.Model.HasCalibrationMetadata, html.EscapeString(d.Model.SHA256), html.EscapeString(strings.Join(d.Model.Taxonomy, ", ")))
	if d.Model.Dummy {
		w.WriteString(`<p>Random dummy weights: predictions carry no evidence value.</p>`)
	}
	if d.Reason != "" {
		fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(d.Reason))
	}
	if d.Error != "" {
		fmt.Fprintf(w, `<p>Model error: %s</p>`, html.EscapeString(d.Error))
	}
	w.WriteString(`<p><a href="GNN_DIAGNOSTICS.json">Full predictions and skip reasons</a></p></div><div class="hotspots-list">`)
	for _, method := range d.Methods[:min(len(d.Methods), 100)] {
		label := method.Status
		if method.PredictedClass != "" {
			label = method.PredictedClass + " · " + method.Outcome
		}
		fmt.Fprintf(w, `<details class="hotspot-card"><summary><strong>%s</strong> · %s</summary><p><code>%s</code></p>`,
			html.EscapeString(method.Method), html.EscapeString(label), html.EscapeString(method.File))
		if method.Reason != "" {
			fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(method.Reason))
		}
		if method.PredictedClass != "" {
			fmt.Fprintf(w, `<p>Graph: %s · Nodes: %d · Class score: %.4f · Top-two margin: %.4f · Normalized entropy: %.4f · Quality gate passed: %v</p>`,
				html.EscapeString(method.GraphKind), method.Nodes, method.Confidence, method.Margin, method.NormalizedEntropy, method.PassesQualityGate)
		}
		w.WriteString(`</details>`)
	}
	if len(d.Methods) > 100 || d.DiagnosticsOmitted > 0 {
		fmt.Fprintf(w, `<p>Showing %d method details. Additional retained diagnostics are available in JSON; %d records were omitted by the diagnostic limit.</p>`, min(len(d.Methods), 100), d.DiagnosticsOmitted)
	}
	w.WriteString(`</div></section>`)
}
