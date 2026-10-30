package main

import "mega-analyzer/pkg/internal/types"

func (o *Output) printBundleResults(result *types.AnalysisResult) {
	s := result.BundleAnalysis
	o.fprintln()
	o.fprintf("BUNDLE ANALYSIS: %s\n", s.Status)
	o.fprintf("  Bundle files: %d\n  Strings scanned: %d / %d\n", s.Files, s.StringsScanned, s.StringsTotal)
	o.fprintf("  Informational observations: %d\n  Risk signals: %d (not a security verdict)\n", s.Observations, s.RiskSignals)
	o.fprintf("  Elapsed (prepare + scan + export): %.3fs\n  DEX/Smali core pipeline only: %.3fs\n", s.ElapsedSeconds, s.PipelineSeconds)
	o.fprintf("  Verdict: %s\n", s.Verdict)
	for _, stage := range result.StaticOutputs {
		o.fprintf("  %s: %s\n", stage.Stage, stage.Status)
		if c := stage.Export; c != nil {
			o.fprintf("    Functions decoded: %d / %d; instructions: %d; output: %d bytes; limit: %s\n", c.DecodedFunctions, c.TotalFunctions, c.Instructions, c.OutputBytes, c.LimitReason)
		}
		if stage.TotalFunctions > 0 {
			o.fprintf("    Graph functions decoded: %d / %d; call sites recorded: %d / %d\n", stage.DecodedFunctions, stage.TotalFunctions, stage.RecordedCalls, stage.TotalCalls)
		}
	}
	o.PrintIssueSummary()
}
