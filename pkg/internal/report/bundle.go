package report

import (
	"fmt"
	"html"
	"strings"
)

func bundleOverviewText(view ReportView) string {
	s := view.BundleAnalysis
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\nEngine: %s\nDate: %s\n", view.Meta.TargetName, view.Meta.EngineVersion, view.Meta.Timestamp)
	fmt.Fprintf(&b, "Status: %s\nVerdict: %s\nBundle files: %d\nStrings scanned: %d / %d\nInformational observations: %d\nRisk signals: %d (not confirmed vulnerabilities)\nElapsed (prepare + scan + export): %.3fs\nDEX/Smali pipeline only: %.3fs\n", s.Status, s.Verdict, s.Files, s.StringsScanned, s.StringsTotal, s.Observations, s.RiskSignals, s.ElapsedSeconds, s.PipelineSeconds)
	b.WriteString("\nURLs, bridge names and library feature strings are inventory, not proof of runtime use or exploitable vulnerabilities. Hermes disassembly/metadata is not recovered JavaScript; binary patch/recompile is unsupported.\n")
	for _, st := range view.StaticOutputs {
		fmt.Fprintf(&b, "\n%s: %s (%s)\n", st.Stage, st.Status, st.Path)
		if c := st.Export; c != nil {
			fmt.Fprintf(&b, "  Functions decoded: %d / %d; scanned: %d; failed: %d; skipped: %d\n  Instructions: %d; bytecode decoded: %d / %d bytes; text: %d bytes\n  Limits: %d functions / %d bytecode bytes / %d instructions / %d output bytes\n", c.DecodedFunctions, c.TotalFunctions, c.ScannedFunctions, c.FailedFunctions, c.SkippedFunctions, c.Instructions, c.DecodedBytecodeBytes, c.TotalBytecodeBytes, c.OutputBytes, c.FunctionLimit, c.BytecodeLimit, c.InstructionLimit, c.OutputLimit)
			if c.LimitReason != "" {
				fmt.Fprintf(&b, "  Limit reached: %s\n", c.LimitReason)
			}
		}
		if st.TotalFunctions > 0 {
			fmt.Fprintf(&b, "  Graph functions decoded: %d / %d; call sites recorded: %d / %d\n", st.DecodedFunctions, st.TotalFunctions, st.RecordedCalls, st.TotalCalls)
		}
		for _, d := range st.Diagnostics {
			fmt.Fprintf(&b, "  %s\n", d)
		}
	}
	return b.String()
}

func (r *HTMLReporter) buildBundleOverview(sb htmlWriter, view ReportView) {
	sb.WriteString(`<section class="hero" id="overview"><div class="hero-content"><h1 class="hero-title">JS/Hermes Bundle Analysis Report</h1><div class="risk-badge">NOT ASSESSED — BUNDLE SCOPE ONLY</div><p>` + html.EscapeString(view.Meta.TargetName) + `</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere">` + html.EscapeString(bundleOverviewText(view)) + `</pre></div></section>`)
}

func (r *MarkdownRenderer) renderBundleOverview(view ReportView) {
	// Indented code keeps even arbitrary diagnostic strings out of Markdown tags/fences.
	r.sb.WriteString("## Scope and coverage\n\n")
	for _, line := range strings.Split(bundleOverviewText(view), "\n") {
		r.sb.WriteString("    " + line + "\n")
	}
	r.sb.WriteString("\n")
}
