package jspatcher

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/apkloader"
)

var hermesEndpointRE = regexp.MustCompile(`(?i)\b(?:https?|wss?)://[a-z0-9._~-]+(?::[0-9]{1,5})?(?:/[a-z0-9._~!$&'()*+,;=:@%/?#-]*)?`)

func analyzeHermes(data []byte, path string) *HermesAnalysis {
	return analyzeHermesContext(context.Background(), data, path, "large")
}

func analyzeHermesContext(ctx context.Context, data []byte, path, budget string) *HermesAnalysis {
	analysis := &HermesAnalysis{Path: path, Status: "complete", Version: apkloader.HermesBytecodeVersion(data)}
	index, err := apkloader.ParseHermesBytecode(data)
	if err != nil {
		analysis.ParseError = err.Error()
		analysis.Status = "failed"
		if errors.Is(err, apkloader.ErrUnsupportedHermes) {
			analysis.Status = "unsupported"
		}
		analysis.Diagnostics = append(analysis.Diagnostics, err.Error())
		analysis.GraphCoverage.Status = analysis.Status
		return analysis
	}
	analysis.Parsed = true
	analysis.Version = index.Header.Version
	analysis.StringCount = len(index.Strings)
	analysis.FunctionCount = len(index.Functions)
	analysis.ModuleCount = len(index.Modules)
	analysis.Status = index.AnalysisStatus
	analysis.TotalStrings, analysis.TotalFunctions, analysis.TotalModules = index.Header.StringCount, index.Header.FunctionCount, index.Header.CJSModuleCount
	analysis.Diagnostics = append(analysis.Diagnostics, index.Diagnostics...)

	for _, module := range index.Modules {
		if module.Name != "" && len(analysis.Modules) < 256 {
			analysis.Modules = appendUniqueString(analysis.Modules, module.Name)
		}
	}
	for _, function := range index.Functions {
		if function.Name != "" && len(analysis.FunctionNames) < 256 {
			analysis.FunctionNames = appendUniqueString(analysis.FunctionNames, function.Name)
		}
	}
	for i, item := range index.Strings {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				analysis.Status = "partial"
				analysis.Diagnostics = append(analysis.Diagnostics, err.Error())
				return analysis
			}
		}
		for _, endpoint := range hermesEndpointRE.FindAllString(item.Value, -1) {
			if len(analysis.Endpoints) < 512 {
				analysis.Endpoints = appendUniqueString(analysis.Endpoints, endpoint)
			}
		}
		if containsHermesBridgeToken(item.Value) && len(analysis.Bridges) < 256 {
			analysis.Bridges = appendUniqueString(analysis.Bridges, item.Value)
		}
	}
	limits, budgetErr := apkloader.BundleBudget(budget)
	if budgetErr != nil {
		analysis.Status = "failed"
		analysis.Diagnostics = append(analysis.Diagnostics, budgetErr.Error())
		return analysis
	}
	maxCalls := 250000
	if budget == "compact" {
		maxCalls = 2000
	}
	graph := index.BuildFunctionGraphContext(ctx, limits.MaxFunctions, limits.MaxBytecodeBytes, maxCalls)
	analysis.GraphCoverage = graph.Coverage
	if graph.Coverage.Status != "complete" {
		analysis.Status = graph.Coverage.Status
	}
	for _, diagnostic := range graph.Coverage.Diagnostics {
		analysis.Diagnostics = appendUniqueString(analysis.Diagnostics, diagnostic)
	}
	if analysis.FunctionCount > len(analysis.FunctionNames) {
		analysis.Diagnostics = append(analysis.Diagnostics, fmt.Sprintf("Function-name preview: %d/%d; full function coverage is reported separately", len(analysis.FunctionNames), analysis.FunctionCount))
	}
	if len(analysis.Endpoints) >= 512 || len(analysis.Bridges) >= 256 {
		analysis.Diagnostics = append(analysis.Diagnostics, "Endpoint/bridge preview limit reached")
		analysis.Status = "partial"
	}
	for _, edge := range graph.Edges {
		var calleeID *uint32
		callee := ""
		if edge.Resolved {
			id := edge.Callee
			calleeID = &id
			callee = hermesFunctionName(index, edge.Callee)
		}
		analysis.CallEdges = append(analysis.CallEdges, HermesCallEdgeSummary{
			Caller:   hermesFunctionName(index, edge.Caller),
			Callee:   callee,
			Offset:   edge.Offset,
			CallerID: edge.Caller, CalleeID: calleeID, Kind: edge.Kind, Confidence: edge.Confidence,
			Resolved: edge.Resolved, FunctionOffset: edge.FunctionOffset,
			CalleeRegister: edge.CalleeRegister, BuiltinID: edge.BuiltinID,
		})
	}
	return analysis
}

func hermesFunctionName(index *apkloader.HermesIndex, id uint32) string {
	if int(id) < len(index.Functions) {
		return index.Functions[id].Name
	}
	return ""
}

func containsHermesBridgeToken(value string) bool {
	for _, token := range []string{"NativeModules", "TurboModuleRegistry", "__fbBatchedBridge", "registerCallableModule", "com.facebook.react"} {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
