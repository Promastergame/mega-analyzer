package evidencegraph

import (
	"fmt"
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func (b *builder) addFindings(result *types.AnalysisResult, target string) {
	incomplete := result.DataFlowStats.LimitReached || result.Coverage.LimitReached || (result.Run != nil && result.Run.Status != "complete")
	for index, f := range result.Findings {
		key := f.Fingerprint
		if key == "" { key = f.ID }
		if key == "" { key = strconv.Itoa(index) }
		attrs := map[string]string{"finding_id": f.ID, "fingerprint": f.Fingerprint, "rule_id": f.RuleID, "severity": f.Severity, "analysis_incomplete": strconv.FormatBool(incomplete)}
		if result.Run != nil { attrs["run_id"] = result.Run.ID; attrs["artifact_sha256"] = result.Run.ArtifactSHA256 }
		id := b.addNode(types.EvidenceNode{ID: stableID("finding", f.RuleID, key), Kind: "finding", Label: f.Title, Description: f.Description, Score: f.Confidence, Attributes: attrs})
		b.addEdge(target, id, "reports", "typed finding")
		for _, loc := range f.Locations {
			if loc.File != "" { b.addEdge(id, b.fileNode(target, loc.File), "located_in", "source location") }
		}
		for i, ev := range f.Evidence {
			eid := b.addNode(types.EvidenceNode{Kind: "finding_evidence", Label: ev.Type, Description: ev.Description, Path: ev.Location.File, Method: ev.Location.Method,
				Attributes: map[string]string{"owner": id, "position": strconv.Itoa(i), "sha256": ev.Digest, "snippet": ev.Snippet, "line": strconv.Itoa(ev.Location.Line)}})
			relation := "backed_by"
			if ev.Type == "runtime" || ev.Type == "observation" { relation = "reported_observation" }
			b.addEdge(id, eid, relation, "saved evidence")
		}
		for _, p := range f.Provenance {
			pid := b.addNode(types.EvidenceNode{Kind: "provenance", Label: p.Engine, Description: p.Detector, Path: p.SourceArtifact,
				Attributes: map[string]string{"owner": id, "rule_id": p.RuleID, "artifact_sha256": p.ArtifactSHA256, "run_id": p.RunID}})
			b.addEdge(id, pid, "produced_by", "detector provenance")
		}
		b.addSteps(id, f.Steps)
	}
	for index, flow := range result.DataFlows {
		owner := ""
		for _, f := range result.Findings {
			if f.RuleID != "dataflow."+flow.Category || f.Description != flow.Source+" flows to "+flow.Sink { continue }
			for _, loc := range f.Locations {
				if cleanPath(loc.File) == cleanPath(flow.Location.File) && loc.Method == flow.Location.Method && loc.Line == flow.Location.Line {
					owner = stableID("finding", f.RuleID, f.Fingerprint)
				}
			}
		}
		attrs := map[string]string{"source": flow.Source, "sink": flow.Sink, "category": flow.Category, "owner": owner, "position": strconv.Itoa(index), "analysis_incomplete": strconv.FormatBool(incomplete)}
		id := b.addNode(types.EvidenceNode{Kind: "data_flow", Label: flow.ExploitChain, Path: flow.Location.File, Method: flow.Location.Method, Score: flow.Confidence, Attributes: attrs})
		if owner != "" { b.addEdge(owner, id, "derived_from", "saved source-to-sink analysis") } else {
			b.addEdge(target, id, "reports", "data flow")
			steps := make([]finding.Step, len(flow.Path))
			for i, s := range flow.Path { steps[i] = finding.Step{File: s.File, Method: s.Method, Type: s.Type, Line: s.Line} }
			b.addSteps(id, steps)
		}
	}
}

func (b *builder) addSteps(owner string, steps []finding.Step) {
	previous := owner
	for i, step := range steps {
		id := b.addNode(types.EvidenceNode{Kind: "path_step", Label: fmt.Sprintf("%d · %s", i+1, step.Type), Path: step.File, Method: step.Method,
			Attributes: map[string]string{"owner": owner, "position": strconv.Itoa(i), "step_type": step.Type, "line": strconv.Itoa(step.Line)}})
		relation := "next_step"
		if i == 0 { relation = "has_path" }
		label := "static data flow"
		if strings.Contains(step.Type, "unresolved") { label = "unresolved boundary" }
		b.addEdge(previous, id, relation, label)
		previous = id
	}
}
