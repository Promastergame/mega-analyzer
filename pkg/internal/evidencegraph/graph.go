package evidencegraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

const (
	graphVersion  = "2"
	maxChainNodes = 128
	maxChainEdges = 256
)

type builder struct {
	nodes map[string]types.EvidenceNode
	edges map[string]types.EvidenceEdge
	files map[string]string
}

func Build(result *types.AnalysisResult) *types.EvidenceGraph {
	if result == nil {
		return nil
	}
	b := &builder{nodes: make(map[string]types.EvidenceNode), edges: make(map[string]types.EvidenceEdge), files: make(map[string]string)}
	targetID := b.addNode(types.EvidenceNode{Kind: "target", Label: targetLabel(result),
		// Report-safe: no absolute local paths (temp extraction dirs,
		// workspace folders) in a shareable evidence graph.
		Path: result.ShareableTargetName()})
	b.addFindings(result, targetID)

	for _, hotspot := range result.Hotspots {
		fileID := b.fileNode(targetID, hotspot.Path)
		hotspotID := b.addNode(types.EvidenceNode{
			Kind: "hotspot", Label: filepath.Base(hotspot.Path), Description: strings.Join(hotspot.Reasons, "; "),
			Path: cleanPath(hotspot.Path), Score: hotspot.Score,
			Attributes: map[string]string{"match_count": fmt.Sprint(hotspot.MatchCount), "critical_count": fmt.Sprint(hotspot.CriticalCount)},
		})
		b.addEdge(hotspotID, fileID, "observed_in", "")
		for _, dp := range hotspot.DecisionPoints {
			if strings.TrimSpace(dp.Method) == "" {
				continue
			}
			methodID := b.addNode(types.EvidenceNode{Kind: "method", Label: dp.Method, Description: dp.Description, Path: cleanPath(hotspot.Path), Method: dp.Method, Score: dp.Confidence})
			b.addEdge(fileID, methodID, "contains", "")
			b.addEdge(methodID, hotspotID, "supports", "decision point")
		}
	}

	filePaths := make([]string, 0, len(result.Files))
	for path := range result.Files {
		filePaths = append(filePaths, path)
	}
	sort.Strings(filePaths)
	for _, path := range filePaths {
		analysis := result.Files[path]
		if analysis == nil || len(analysis.RecoveredArtifacts) == 0 {
			continue
		}
		fileID := b.fileNode(targetID, path)
		for _, artifact := range analysis.RecoveredArtifacts {
			artifactID := b.addNode(types.EvidenceNode{Kind: "recovered_artifact", Label: artifact.Kind, Description: artifact.Preview, Path: cleanPath(path), Method: artifact.SourceMethod, Attributes: map[string]string{"artifact_id": artifact.ID, "sha256": artifact.SHA256, "status": artifact.Status, "source_proof": artifact.SourceProofID}})
			if artifact.SourceMethod != "" {
				methodID := b.addNode(types.EvidenceNode{Kind: "method", Label: artifact.SourceMethod, Path: cleanPath(path), Method: artifact.SourceMethod})
				b.addEdge(fileID, methodID, "contains", "")
				b.addEdge(artifactID, methodID, "derived_from", artifact.SourceProofKind)
			} else {
				b.addEdge(artifactID, fileID, "derived_from", artifact.SourceProofKind)
			}
		}
	}

	for _, correlation := range result.Correlations {
		corrID := b.addNode(types.EvidenceNode{
			Kind: "correlation", Label: correlation.Type.String(), Description: correlation.Description, Score: correlation.Score,
			Attributes: map[string]string{"category": string(correlation.Category)},
		})
		for _, path := range correlation.Files {
			fileID := b.fileNode(targetID, path)
			b.addEdge(corrID, fileID, "correlates_with", "")
		}
	}

	for _, finding := range result.GNNFindings {
		// Dummy-weight findings are random outputs; they are provenance
		// noise, not evidence, so they never enter the graph.
		if finding.Dummy {
			continue
		}
		gnnID := b.addNode(types.EvidenceNode{
			Kind: "gnn", Label: finding.VulnClass, Description: "GNN vulnerability cross-check", Path: cleanPath(finding.FilePath), Method: finding.Method,
			Score: float64(finding.Confidence), Attributes: map[string]string{"model_role": "cross_check"},
		})
		if finding.FilePath != "" {
			fileID := b.fileNode(targetID, finding.FilePath)
			b.addEdge(gnnID, fileID, "observed_in", "")
			if finding.Method != "" {
				methodID := b.addNode(types.EvidenceNode{Kind: "method", Label: finding.Method, Path: cleanPath(finding.FilePath), Method: finding.Method})
				b.addEdge(fileID, methodID, "contains", "")
				b.addEdge(gnnID, methodID, "supports", "model cross-check")
			}
		}
	}

	if n := result.NcerResult; n != nil {
		ncerID := b.addNode(types.EvidenceNode{
			Kind: "ncer", Label: "NCER causal reconciliation", Description: "Network claim-evidence reconciliation result", Score: float64(n.DCausal),
			Attributes: map[string]string{"coverage_quality": fmt.Sprintf("%.4f", n.CoverageQuality), "evidence_verified": fmt.Sprint(n.EvidenceVerified)},
		})
		b.addEdge(targetID, ncerID, "derived_from", "dynamic analysis")
		for _, ref := range n.EvidenceRefs {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			evidenceID := b.addNode(types.EvidenceNode{Kind: "evidence_ref", Label: shortRef(ref), Description: "Content-addressed SHA-256 evidence", Attributes: map[string]string{"sha256": ref, "verified": fmt.Sprint(n.EvidenceVerified)}})
			b.addEdge(ncerID, evidenceID, "backed_by", "")
		}
	}

	if len(b.nodes) <= 1 && len(b.edges) == 0 {
		return nil
	}
	return b.finish()
}

func Query(graph *types.EvidenceGraph, nodeID, path string) (*types.EvidenceChain, error) {
	if graph == nil {
		return nil, fmt.Errorf("evidence graph is not available")
	}
	rootID := strings.TrimSpace(nodeID)
	if rootID == "" && strings.TrimSpace(path) != "" {
		want := cleanPath(path)
		for _, node := range graph.Nodes {
			if cleanPath(node.Path) == want && node.Kind == "file" {
				rootID = node.ID
				break
			}
		}
	}
	if rootID == "" {
		return nil, fmt.Errorf("node id or file path is required")
	}
	nodes := make(map[string]types.EvidenceNode, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
	}
	root, ok := nodes[rootID]
	if !ok {
		for _, node := range graph.Nodes {
			if node.Kind == "finding" && (node.Attributes["finding_id"] == rootID || node.Attributes["fingerprint"] == rootID) {
				if ok {
					return nil, fmt.Errorf("ambiguous finding identity")
				}
				root, ok = node, true
			}
		}
		if ok {
			rootID = root.ID
		}
	}
	if !ok {
		return nil, fmt.Errorf("evidence node %q not found", rootID)
	}

	// Index valid edges once. A query walks only its connected evidence,
	// without rescanning the entire graph at every node.
	adjacent := make(map[string][]types.EvidenceEdge, len(nodes))
	for _, edge := range graph.Edges {
		if _, ok := nodes[edge.From]; !ok {
			continue
		}
		if _, ok := nodes[edge.To]; !ok {
			continue
		}
		if edge.ID == "" {
			edge.ID = stableID("edge", edge.From, edge.To, edge.Relation, edge.Label, canonicalMap(edge.Attributes))
		}
		adjacent[edge.From] = append(adjacent[edge.From], edge)
		adjacent[edge.To] = append(adjacent[edge.To], edge)
	}
	for id := range adjacent {
		sort.Slice(adjacent[id], func(i, j int) bool { return adjacent[id][i].ID < adjacent[id][j].ID })
	}

	seen := map[string]bool{rootID: true}
	seenEdges := make(map[string]bool)
	queue := []string{rootID}
	chainEdges := make([]types.EvidenceEdge, 0)
	truncated := false
	for len(queue) > 0 && len(chainEdges) < maxChainEdges {
		current := queue[0]
		queue = queue[1:]
		// The shared target gives context, but is not evidence linking every
		// file to every other file. An explicit target query can expand it.
		if current != rootID && nodes[current].Kind == "target" {
			continue
		}
		// Shared file/method hubs are context, not proof that unrelated findings
		// belong to this investigation. Finding-owned nodes carry their own paths.
		if root.Kind == "finding" && current != rootID {
			kind := nodes[current].Kind
			if kind == "file" || kind == "method" || kind == "finding" {
				continue
			}
		}
		for _, edge := range adjacent[current] {
			if seenEdges[edge.ID] {
				continue
			}
			next := edge.To
			if next == current {
				next = edge.From
			}
			if root.Kind == "finding" && nodes[next].Kind == "finding" && next != rootID {
				continue
			}
			if !seen[next] {
				if len(seen) >= maxChainNodes {
					truncated = true
					continue
				}
				seen[next] = true
				queue = append(queue, next)
			}
			seenEdges[edge.ID] = true
			chainEdges = append(chainEdges, edge)
			if len(chainEdges) >= maxChainEdges {
				truncated = true
				break
			}
		}
	}
	chainNodes := make([]types.EvidenceNode, 0, len(seen))
	for id := range seen {
		if node, exists := nodes[id]; exists {
			chainNodes = append(chainNodes, node)
		}
	}
	sort.Slice(chainNodes, func(i, j int) bool { return chainNodes[i].ID < chainNodes[j].ID })
	sort.Slice(chainEdges, func(i, j int) bool { return chainEdges[i].ID < chainEdges[j].ID })
	chain := &types.EvidenceChain{RootID: rootID, Summary: fmt.Sprintf("%s is connected to %d evidence node(s) by %d typed relation(s).", root.Label, len(chainNodes)-1, len(chainEdges)), Nodes: chainNodes, Edges: chainEdges, Truncated: truncated}
	if truncated {
		chain.Warnings = append(chain.Warnings, "Evidence query reached its node or edge limit; this view is incomplete.")
	}
	if root.Attributes["analysis_incomplete"] == "true" {
		chain.Warnings = append(chain.Warnings, "The source analysis is incomplete; absence of an edge is not evidence of safety.")
	}
	return chain, nil
}

func (b *builder) fileNode(targetID, path string) string {
	path = cleanPath(path)
	if id := b.files[path]; id != "" {
		return id
	}
	label := filepath.Base(filepath.FromSlash(path))
	if label == "." || label == "" {
		label = path
	}
	id := b.addNode(types.EvidenceNode{Kind: "file", Label: label, Path: path})
	b.files[path] = id
	b.addEdge(targetID, id, "contains", "")
	return id
}

func (b *builder) addNode(node types.EvidenceNode) string {
	node.Path = cleanPath(node.Path)
	if node.ID == "" {
		node.ID = stableID("node", node.Kind, node.Path, node.Method, node.Label, node.Description, canonicalMap(node.Attributes))
	}
	if existing, ok := b.nodes[node.ID]; ok {
		if node.Score > existing.Score {
			existing.Score = node.Score
			b.nodes[node.ID] = existing
		}
		return node.ID
	}
	b.nodes[node.ID] = node
	return node.ID
}

func (b *builder) addEdge(from, to, relation, label string) {
	if from == "" || to == "" {
		return
	}
	basis := "static_analysis"
	if relation == "correlates_with" || relation == "supports" {
		basis = "assessment"
	}
	if relation == "reported_observation" || label == "dynamic analysis" {
		basis = "observation"
	}
	edge := types.EvidenceEdge{From: from, To: to, Relation: relation, Label: label, Attributes: map[string]string{"basis": basis}}
	edge.ID = stableID("edge", from, to, relation, label)
	b.edges[edge.ID] = edge
}

func (b *builder) finish() *types.EvidenceGraph {
	graph := &types.EvidenceGraph{Version: graphVersion, Nodes: make([]types.EvidenceNode, 0, len(b.nodes)), Edges: make([]types.EvidenceEdge, 0, len(b.edges))}
	for _, node := range b.nodes {
		graph.Nodes = append(graph.Nodes, node)
	}
	for _, edge := range b.edges {
		graph.Edges = append(graph.Edges, edge)
	}
	sort.Slice(graph.Nodes, func(i, j int) bool { return graph.Nodes[i].ID < graph.Nodes[j].ID })
	sort.Slice(graph.Edges, func(i, j int) bool { return graph.Edges[i].ID < graph.Edges[j].ID })
	return graph
}

func targetLabel(result *types.AnalysisResult) string {
	if result.AppPackage != "" {
		return result.AppPackage
	}
	if base := filepath.Base(result.TargetDir); base != "." && base != "" {
		return base
	}
	return "analysis target"
}

func cleanPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	// Normalize Windows-style separators before cleaning so paths recorded on
	// one OS (e.g. "smali\com\Main.smali") match forward-slash node paths and
	// query lookups on every platform.
	return filepath.ToSlash(filepath.Clean(strings.ReplaceAll(strings.TrimSpace(path), "\\", "/")))
}
func shortRef(ref string) string {
	if len(ref) > 16 {
		return ref[:16]
	}
	return ref
}
func stableID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}
func canonicalMap(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(values[key])
		b.WriteByte(0)
	}
	return b.String()
}
