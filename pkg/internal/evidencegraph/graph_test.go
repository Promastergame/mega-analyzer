package evidencegraph

import (
	"encoding/json"
	"reflect"
	"testing"
	"strconv"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func sampleResult() *types.AnalysisResult {
	return &types.AnalysisResult{
		TargetDir: "app", AppPackage: "com.example.app",
		Hotspots:     []types.Hotspot{{Path: "smali/com/example/Main.smali", Score: 81, MatchCount: 2, CriticalCount: 1, Reasons: []string{"suspicious reflection"}}},
		Correlations: []types.Correlation{{Type: types.CorrelationDataFlow, Files: []string{"smali/com/example/Main.smali"}, Description: "source reaches sink", Score: .9}},
		GNNFindings:  []types.GNNFinding{{FilePath: "smali/com/example/Main.smali", Method: "send", VulnClass: "exfiltration", Confidence: .88}},
		NcerResult:   &types.NcerCausalResult{DCausal: .25, CoverageQuality: .75, EvidenceRefs: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, EvidenceVerified: true, EvidenceCount: 1},
	}
}

func TestBuildDeterministicAndNoDanglingEdges(t *testing.T) {
	first := Build(sampleResult())
	second := Build(sampleResult())
	if !reflect.DeepEqual(first, second) {
		t.Fatal("graph must be deterministic")
	}
	ids := make(map[string]bool)
	for _, node := range first.Nodes {
		if ids[node.ID] {
			t.Fatalf("duplicate node %s", node.ID)
		}
		ids[node.ID] = true
	}
	for _, edge := range first.Edges {
		if !ids[edge.From] || !ids[edge.To] {
			t.Fatalf("dangling edge %#v", edge)
		}
	}
}

func TestQueryByFileAndJSONRoundTrip(t *testing.T) {
	graph := Build(sampleResult())
	chain, err := Query(graph, "", "smali\\com\\example\\Main.smali")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Nodes) < 3 || len(chain.Edges) < 2 {
		t.Fatalf("unexpected chain: %#v", chain)
	}
	data, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	var decoded types.EvidenceGraph
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(graph, &decoded) {
		t.Fatal("JSON round-trip changed graph")
	}
}

func TestBuildEmptyReturnsNil(t *testing.T) {
	if got := Build(&types.AnalysisResult{TargetDir: "app"}); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
}

func TestFindingQueryPreservesPathAndDoesNotJoinOtherFindings(t *testing.T) {
	r := &types.AnalysisResult{TargetDir: "app", Findings: []finding.Finding{
		{ID: "command", Fingerprint: "a", RuleID: "dataflow.command_injection", Title: "Command", Locations: []finding.Location{{File: "shared.smali"}},
			Steps: []finding.Step{{Method: "read", Type: "source"}, {Method: "bridge", Type: "propagation"}, {Method: "run", Type: "sink"}},
			Evidence: []finding.Evidence{{Type: "code", Snippet: "exec(input)"}}},
		{ID: "unrelated", Fingerprint: "b", RuleID: "other", Title: "Other", Locations: []finding.Location{{File: "shared.smali"}}},
	}}
	chain, err := Query(Build(r), "command", "")
	if err != nil { t.Fatal(err) }
	steps := map[string]string{}
	for _, node := range chain.Nodes {
		if node.Attributes["finding_id"] == "unrelated" { t.Fatal("shared file contaminated finding evidence") }
		if node.Kind == "path_step" { steps[node.Attributes["position"]] = node.Method }
	}
	if steps["0"] != "read" || steps["1"] != "bridge" || steps["2"] != "run" { t.Fatal(steps) }
	if chain.Truncated { t.Fatal("short chain marked truncated") }
}

func TestFindingQueryReportsTruncation(t *testing.T) {
	f := finding.Finding{ID: "large", Fingerprint: "large", RuleID: "test"}
	for i := 0; i < 200; i++ { f.Steps = append(f.Steps, finding.Step{Method: strconv.Itoa(i), Type: "propagation"}) }
	chain, err := Query(Build(&types.AnalysisResult{Findings: []finding.Finding{f}}), "large", "")
	if err != nil { t.Fatal(err) }
	if !chain.Truncated || len(chain.Warnings) == 0 || len(chain.Nodes) > maxChainNodes { t.Fatalf("unmarked truncation: %+v", chain) }
}
