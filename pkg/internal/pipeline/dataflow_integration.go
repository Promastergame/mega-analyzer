package pipeline

import (
	"context"
	"mega-analyzer/pkg/internal/dataflow"

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
