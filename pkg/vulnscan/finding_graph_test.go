package vulnscan

import (
	"strings"
	"testing"
)

func graphFinding(id, urlStr, param string, sev Severity, conf float64) Finding {
	f := Finding{Vulnerability: Vulnerability{ID: id, URL: urlStr, Parameter: param, Severity: sev}}
	f.Confidence = conf
	return f
}

func TestBuildFindingGraph_ColocationEdges(t *testing.T) {
	g := BuildFindingGraph([]Finding{
		graphFinding("WS-XSS-001", "http://a.com/search", "q", SeverityHigh, 0.8),
		graphFinding("WS-CRLF-001", "http://a.com/search", "q", SeverityMedium, 0.6),
	})
	if len(g.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(g.Nodes))
	}
	var kinds []string
	for _, e := range g.Edges {
		kinds = append(kinds, string(e.Kind))
	}
	joined := strings.Join(kinds, ",")
	if !strings.Contains(joined, string(EdgeSameEndpoint)) || !strings.Contains(joined, string(EdgeSameParameter)) {
		t.Fatalf("expected same_endpoint + same_parameter edges, got %v", kinds)
	}
	// CRLF -> XSS flow edge must be present and directed.
	foundFlow := false
	for _, e := range g.Edges {
		if e.Kind == EdgeAttackFlow && g.Nodes[e.From].ID == "WS-CRLF-001" && g.Nodes[e.To].ID == "WS-XSS-001" {
			foundFlow = true
		}
	}
	if !foundFlow {
		t.Error("expected directed CRLF -> XSS attack-flow edge")
	}
}

func TestAttackPaths_TwoStage(t *testing.T) {
	g := BuildFindingGraph([]Finding{
		graphFinding("WS-LFI-001", "http://a.com/inc", "page", SeverityHigh, 0.7),
		graphFinding("WS-SECRET-AWS", "http://a.com/config", "", SeverityCritical, 0.9),
	})
	paths := g.AttackPaths(4)
	if len(paths) != 1 || len(paths[0]) != 2 {
		t.Fatalf("expected exactly one 2-node path, got %v", paths)
	}
	meta := SynthesizeAttackPathFindings(g, paths)
	if len(meta) != 1 {
		t.Fatalf("expected one meta finding, got %d", len(meta))
	}
	m := meta[0]
	if m.ID != "WS-ATTACK-PATH-1" || !m.Correlated {
		t.Errorf("unexpected meta finding identity: %s correlated=%v", m.ID, m.Correlated)
	}
	if len(m.Sources) != 2 {
		t.Errorf("expected 2 sources, got %v", m.Sources)
	}
	if m.Severity != SeverityCritical {
		t.Errorf("path severity must be the max member severity, got %v", m.Severity)
	}
	if !strings.Contains(m.Name, "lfi -> secret") {
		t.Errorf("path name must describe the family chain, got %q", m.Name)
	}
}

func TestAttackPaths_CrossHostNoChain(t *testing.T) {
	g := BuildFindingGraph([]Finding{
		graphFinding("WS-LFI-001", "http://a.com/inc", "page", SeverityHigh, 0.7),
		graphFinding("WS-SECRET-AWS", "http://b.com/config", "", SeverityCritical, 0.9),
	})
	if paths := g.AttackPaths(4); len(paths) != 0 {
		t.Fatalf("cross-host primitives must not chain, got %v", paths)
	}
}

func TestAttackPaths_ThreeStagePromotesSeverity(t *testing.T) {
	g := BuildFindingGraph([]Finding{
		graphFinding("WS-LFI-001", "http://a.com/inc", "page", SeverityMedium, 0.7),
		graphFinding("WS-SECRET-GEN", "http://a.com/config", "", SeverityMedium, 0.6),
		graphFinding("WS-IDOR-001", "http://a.com/api", "user_id", SeverityMedium, 0.65),
	})
	paths := g.AttackPaths(4)
	if len(paths) != 1 || len(paths[0]) != 3 {
		t.Fatalf("expected one 3-node path, got %v", paths)
	}
	meta := SynthesizeAttackPathFindings(g, paths)
	if len(meta) != 1 {
		t.Fatalf("expected one meta finding, got %d", len(meta))
	}
	if meta[0].Severity != SeverityHigh {
		t.Errorf("3-stage Medium chain must be promoted to High, got %v", meta[0].Severity)
	}
	// Weakest link (0.6) + one multi-stage bonus (0.05).
	if meta[0].Confidence < 0.64 || meta[0].Confidence > 0.66 {
		t.Errorf("expected confidence ~0.65, got %v", meta[0].Confidence)
	}
}

func TestBuildFindingGraph_ExcludesCorrelatedMeta(t *testing.T) {
	meta := graphFinding("WS-CHAIN-ATO", "http://a.com/x", "", SeverityCritical, 0.8)
	meta.Correlated = true
	g := BuildFindingGraph([]Finding{
		meta,
		graphFinding("WS-XSS-001", "http://a.com/search", "q", SeverityHigh, 0.8),
	})
	if len(g.Nodes) != 1 {
		t.Fatalf("correlated meta-findings must not become graph nodes, got %d nodes", len(g.Nodes))
	}
}

func TestSynthesizeAttackPaths_NoFindings(t *testing.T) {
	if got := SynthesizeAttackPaths(nil); len(got) != 0 {
		t.Fatalf("empty input must yield no paths, got %d", len(got))
	}
}
