package pipeline

import (
	"context"
	"strings"

	"mega-analyzer/pkg/internal/analyzer"
	"mega-analyzer/pkg/internal/dataflow"
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/manifestaudit"

	"mega-analyzer/pkg/internal/contentcache"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"
)

type dataFlowCacheAdapter struct {
	cache *contentcache.PipelineCache
}

func (a dataFlowCacheAdapter) Get(signature string, body []string) ([]byte, bool) {
	return a.cache.GetMethodTaintData(signature, body)
}

func (a dataFlowCacheAdapter) Put(signature string, body []string, data []byte) {
	a.cache.PutMethodTaintData(signature, body, data)
}

func (p *Pipeline) runDataFlow(ctx context.Context) {
	// Budget priority and entry-point labels need manifest context: the app
	// package is sliced before libraries, and only effectively exported
	// components are called IPC entry points.
	if p.dataFlow != nil {
		if p.result.AppPackage != "" {
			p.dataFlow.SetAppPackage(p.result.AppPackage)
		}
		if exported := p.exportedComponentSet(); len(exported) > 0 {
			p.dataFlow.SetExportedComponents(exported)
		}
	}
	analysis := p.dataFlow.Analyze(ctx)
	p.result.DataFlows = make([]types.DataFlowFinding, 0, len(analysis.Findings))
	p.result.DataFlowObservations = make([]types.DataFlowFinding, 0, len(analysis.Observations))
	allFlows := append(append([]dataflow.Finding(nil), analysis.Findings...), analysis.Observations...)
	for _, item := range allFlows {
		path := make([]types.DataFlowStep, len(item.Path))
		for i, step := range item.Path {
			path[i] = types.DataFlowStep{File: step.File, Method: step.Method, Type: step.Type, Line: step.Line}
		}
		converted := types.DataFlowFinding{
			Source: item.Source, Sink: item.Sink, Category: item.Category,
			ExploitChain: item.ExploitChain,
			Label:        uint64(item.Label), Severity: item.Severity, Confidence: item.Confidence,
			Location: types.SourceLocation{File: item.Location.File, Line: item.Location.Line, Method: item.Location.Method},
			Path:     path,
		}
		if item.Category == "untrusted_log_input" {
			p.result.DataFlowObservations = append(p.result.DataFlowObservations, converted)
		} else {
			p.result.DataFlows = append(p.result.DataFlows, converted)
		}
	}
	p.result.DataFlowStats = types.DataFlowStats{
		IncompatibleCastFlowsPruned: analysis.Stats.IncompatibleCastFlowsPruned,
		SliceSteps:                  analysis.Stats.SliceSteps,
		SliceLimitReached:           analysis.Stats.SliceLimitReached,
		Cancelled:                   analysis.Stats.Cancelled,
		SinksVisited:                analysis.Stats.SinksVisited,
		SlicesTruncated:             analysis.Stats.SlicesTruncated,
		CFGMethods:                  analysis.Stats.CFGMethods,
		CFGNodes:                    analysis.Stats.CFGNodes,
		CFGEdges:                    analysis.Stats.CFGEdges,
		CFGIncompleteMethods:        analysis.Stats.CFGIncompleteMethods,
		ReachingDefinitionSteps:     analysis.Stats.ReachingDefinitionSteps,
		ReachingDefinitionCacheHits: analysis.Stats.ReachingDefinitionCacheHits,
		UnreachableSinksSkipped:     analysis.Stats.UnreachableSinksSkipped,
		InformationalFlows:          analysis.Stats.InformationalFlows,
		ObservationsOmitted:         analysis.Stats.ObservationsOmitted,
		MethodsDiscovered:           analysis.Stats.MethodsDiscovered,
		MethodsAnalyzed:             analysis.Stats.MethodsAnalyzed,
		MethodsTruncated:            analysis.Stats.MethodsTruncated,
		Iterations:                  analysis.Stats.Iterations,
		CacheHits:                   analysis.Stats.CacheHits,
		CacheMisses:                 analysis.Stats.CacheMisses,
		Flows:                       analysis.Stats.Flows,
		Findings:                    analysis.Stats.Findings,
		LimitReached:                analysis.Stats.LimitReached,
	}
	logger.Info("Data-flow analysis complete",
		"methods", analysis.Stats.MethodsAnalyzed,
		"iterations", analysis.Stats.Iterations,
		"findings", analysis.Stats.Findings,
		"limit_reached", analysis.Stats.LimitReached,
	)
}

// exportedComponentSet returns the dotted names of manifest components with
// effective export, reusing the manifest bridge on the retained manifest
// source. Empty set = unknown (detectors keep legacy behavior).
func (p *Pipeline) exportedComponentSet() map[string]struct{} {
	for _, fa := range p.result.Files {
		if fa == nil || fa.XMLData == nil || fa.XMLData.ManifestSource == "" {
			continue
		}
		manifest, err := bridgeDecodeManifest([]byte(fa.XMLData.ManifestSource))
		if err != nil || manifest == nil {
			continue
		}
		report := manifestaudit.Audit(fa.Path, manifest)
		set := make(map[string]struct{}, len(report.ExportedComponents))
		for _, ec := range report.ExportedComponents {
			if !ec.ExportedEffective {
				continue
			}
			name := strings.TrimPrefix(ec.Name, ".")
			if p.result.AppPackage != "" && !strings.Contains(name, ".") {
				name = p.result.AppPackage + "." + name
			}
			set[name] = struct{}{}
		}
		return set
	}
	return nil
}

// mergeDataflowIntoHotspots projects retained data-flow findings into the
// file-match universe so hotspot scoring and the heatmap see them, then
// recomputes hotspots. Synthetic matches are tagged so the typed-findings
// conversion does not emit them twice.
func (p *Pipeline) mergeDataflowIntoHotspots(scorer *analyzer.Scorer) {
	if p.result == nil || scorer == nil {
		return
	}
	added := 0
	for _, flow := range dedupeDataflows(p.result.DataFlows) {
		item := typedFindingFromDataFlow(flow, nil)
		if item.Kind != finding.KindVulnerability {
			continue
		}
		sev := types.ParseSeverity(item.Severity)
		if sev != types.SeverityHigh && sev != types.SeverityMedium {
			continue
		}
		fa, ok := p.result.Files[flow.Location.File]
		if !ok || fa == nil {
			continue
		}
		source := flow.Source + " -> " + flow.Sink
		if len(source) > 160 {
			source = source[:157] + "..."
		}
		fa.Matches = append(fa.Matches, types.Match{
			SourceLocation: types.SourceLocation{File: fa.Path, Line: flow.Location.Line},
			Categorized:    types.Categorized{Category: types.CategoryDataFlow},
			Scored:         types.Scored{Score: float64(types.GetCategoryInfo(types.CategoryDataFlow).Priority)},
			Text:           "Static data-flow (" + flow.Category + "): " + source,
			Context:        "Retained data-flow path; reachability requires verification",
			Pattern:        flow.Category,
			Severity:       sev,
			Metadata:       map[string]string{"synthetic_dataflow": "true", "detector": "summary_dataflow"},
		})
		p.result.Stats.TotalMatches++
		p.result.MatchesByCategory[types.CategoryDataFlow]++
		added++
	}
	if added == 0 {
		return
	}
	p.result.Hotspots = scorer.CalculateHotspots(p.result.Files, 50)
	types.SortHotspotsByScore(p.result.Hotspots)
	p.stats.HotspotsTotal.Store(int64(len(p.result.Hotspots)))
	logger.Warn("dataflow findings projected into hotspots",
		"synthetic_matches", added, "hotspots", len(p.result.Hotspots))
}
