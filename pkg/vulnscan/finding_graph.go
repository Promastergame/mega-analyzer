package vulnscan

// Finding graph and attack-path synthesis.
//
// Individual findings are points; a graph turns them into topology. Three
// edge kinds are modelled:
//   - same_endpoint: two findings hit the same host+path (co-location),
//   - same_parameter: two findings share a host and an input parameter,
//   - attack_flow: a directed, curated edge between check families where the
//     first primitive realistically enables the second (e.g. file read ->
//     secret disclosure, XSS -> CSRF bypass).
//
// Attack paths are maximal directed walks over attack_flow edges, scoped to a
// single host (cross-host chains are false narratives, matching the
// correlation join condition). Each maximal path becomes one correlated
// meta-finding whose Sources preserve full provenance.

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// EdgeKind classifies the relationship between two findings.
type EdgeKind string

const (
	EdgeSameEndpoint  EdgeKind = "same_endpoint"
	EdgeSameParameter EdgeKind = "same_parameter"
	EdgeAttackFlow    EdgeKind = "attack_flow"
)

// GraphEdge connects two nodes (indices into FindingGraph.Nodes).
type GraphEdge struct {
	From   int
	To     int
	Kind   EdgeKind
	Detail string
}

// FindingGraph is the finding topology for one scan.
type FindingGraph struct {
	Nodes []Finding
	Edges []GraphEdge
}

// flowRule is one curated attack-flow edge between finding families.
type flowRule struct {
	from      string // family of the enabling primitive
	to        string // family of the enabled finding
	narrative string
}

// flowTable encodes realistic attack progression between check families.
// Families are matched by checkFamily, which normalizes legacy and
// registry-bridged IDs (WS-XSS-* and WS-FORM-XSS both map to "xss").
var flowTable = []flowRule{
	{"lfi", "secret", "a file-read primitive can surface configuration files containing hardcoded secrets"},
	{"xxe", "ssrf", "an XML parser that resolves entities can be turned into server-side requests"},
	{"xss", "csrf", "script execution in the victim's session bypasses CSRF token validation"},
	{"redir", "ssrf", "an open redirect lets SSRF payloads pivot through the trusted origin"},
	{"secret", "idor", "leaked credentials or identifiers enable unauthorized direct object access"},
	{"jwt", "idor", "a forgeable token lets an attacker impersonate other object owners"},
	{"crlf", "xss", "response splitting can smuggle markup into downstream responses"},
}

// checkFamily normalizes a finding ID onto its vulnerability family key.
func checkFamily(id string) string {
	upper := strings.ToUpper(id)
	families := []string{
		"XSS", "SQLI", "LFI", "IDOR", "SSRF", "REDIR", "SECRET", "JWT",
		"CSRF", "SSTI", "XXE", "CRLF", "VERB", "HPP", "UPLOAD", "PROTO", "RACE",
	}
	for _, fam := range families {
		if strings.Contains(upper, fam) {
			return strings.ToLower(fam)
		}
	}
	return "other"
}

// findingEndpoint returns host+path for co-location edges, or "" when the
// finding cannot be attributed to an endpoint.
func findingEndpoint(f Finding) string {
	if f.URL == "" {
		return ""
	}
	u, err := url.Parse(f.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host) + u.Path
}

// BuildFindingGraph constructs the graph over the attributed (host-bearing),
// non-correlated findings. Correlated meta-findings are excluded so chains
// never nest inside chains.
func BuildFindingGraph(findings []Finding) *FindingGraph {
	g := &FindingGraph{}
	for _, f := range findings {
		if f.Correlated || findingHost(f) == "" {
			continue
		}
		g.Nodes = append(g.Nodes, f)
	}

	for i := 0; i < len(g.Nodes); i++ {
		for j := i + 1; j < len(g.Nodes); j++ {
			a, b := g.Nodes[i], g.Nodes[j]

			if ea, eb := findingEndpoint(a), findingEndpoint(b); ea != "" && ea == eb {
				g.Edges = append(g.Edges, GraphEdge{From: i, To: j, Kind: EdgeSameEndpoint, Detail: ea})
			}
			if a.Parameter != "" && a.Parameter == b.Parameter && findingHost(a) == findingHost(b) {
				g.Edges = append(g.Edges, GraphEdge{From: i, To: j, Kind: EdgeSameParameter, Detail: a.Parameter})
			}

			// Directed attack-flow edges, both orientations checked. Chains
			// are scoped to one host: an LFI on host A cannot read secrets
			// from host B's config.
			if findingHost(a) == findingHost(b) {
				fa, fb := checkFamily(a.ID), checkFamily(b.ID)
				for _, rule := range flowTable {
					if fa == rule.from && fb == rule.to {
						g.Edges = append(g.Edges, GraphEdge{From: i, To: j, Kind: EdgeAttackFlow, Detail: rule.narrative})
					}
					if fb == rule.from && fa == rule.to {
						g.Edges = append(g.Edges, GraphEdge{From: j, To: i, Kind: EdgeAttackFlow, Detail: rule.narrative})
					}
				}
			}
		}
	}
	sort.SliceStable(g.Edges, func(x, y int) bool {
		ex, ey := g.Edges[x], g.Edges[y]
		if ex.Kind != ey.Kind {
			return ex.Kind < ey.Kind
		}
		if ex.From != ey.From {
			return ex.From < ey.From
		}
		return ex.To < ey.To
	})
	return g
}

// flowAdjacency returns the directed attack-flow adjacency list.
func (g *FindingGraph) flowAdjacency() map[int][]int {
	adj := make(map[int][]int)
	for _, e := range g.Edges {
		if e.Kind == EdgeAttackFlow {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	for _, tos := range adj {
		sort.Ints(tos)
	}
	return adj
}

// AttackPaths returns all maximal directed attack-flow walks of at least two
// nodes, bounded by maxLen nodes. Maximal means the walk cannot be extended;
// prefixes are implied by their extension and are not emitted separately.
func (g *FindingGraph) AttackPaths(maxLen int) [][]int {
	if maxLen < 2 {
		maxLen = 4
	}
	adj := g.flowAdjacency()
	var paths [][]int
	visited := make([]bool, len(g.Nodes))

	var walk func(node int, path []int)
	walk = func(node int, path []int) {
		extended := false
		for _, next := range adj[node] {
			if visited[next] || len(path) >= maxLen {
				continue
			}
			extended = true
			visited[next] = true
			walk(next, append(append([]int{}, path...), next))
			visited[next] = false
		}
		if !extended && len(path) >= 2 {
			paths = append(paths, append([]int{}, path...))
		}
	}

	starts := make([]int, 0, len(adj))
	inDegree := make([]int, len(g.Nodes))
	for from, tos := range adj {
		starts = append(starts, from)
		for _, to := range tos {
			inDegree[to]++
		}
	}
	sort.Ints(starts)
	for _, s := range starts {
		if inDegree[s] > 0 {
			continue // not a path root: reachable from another node
		}
		visited[s] = true
		walk(s, []int{s})
		visited[s] = false
	}
	return paths
}

// SynthesizeAttackPathFindings converts maximal attack paths into correlated
// meta-findings. Severity is the maximum member severity, promoted one level
// for paths of three or more primitives; confidence starts from the weakest
// member (a chain is only as solid as its weakest link) with a small
// multi-stage bonus.
func SynthesizeAttackPathFindings(g *FindingGraph, paths [][]int) []Finding {
	var out []Finding
	for n, path := range paths {
		var fams, narratives, sources []string
		maxSev := SeverityLow
		minConf := 1.0
		for _, idx := range path {
			f := g.Nodes[idx]
			fams = append(fams, checkFamily(f.ID))
			sources = append(sources, f.ID)
			if findingSeverityRank(f.Severity) < findingSeverityRank(maxSev) {
				maxSev = f.Severity
			}
			if f.Confidence < minConf {
				minConf = f.Confidence
			}
		}
		for k := 0; k < len(path)-1; k++ {
			// Find the flow edge narrative between consecutive nodes.
			for _, e := range g.Edges {
				if e.Kind == EdgeAttackFlow && e.From == path[k] && e.To == path[k+1] {
					narratives = append(narratives, e.Detail)
					break
				}
			}
		}

		sev := maxSev
		if len(path) >= 3 {
			sev = promoteSeverity(maxSev)
		}
		conf := minConf + 0.05*float64(len(path)-2)
		if conf > 0.95 {
			conf = 0.95
		}

		meta := Finding{Vulnerability: Vulnerability{
			ID:          fmt.Sprintf("WS-ATTACK-PATH-%d", n+1),
			Name:        fmt.Sprintf("Attack Path: %s", strings.Join(fams, " -> ")),
			Description: fmt.Sprintf("A multi-stage attack path of %d primitives was chained on the same host: %s.", len(path), strings.Join(narratives, "; ")),
			Severity:    sev,
			Mitigation:  "Break the chain at its earliest primitive: remediate the first finding in the path before the downstream ones become exploitable.",
		}}
		meta.Correlated = true
		meta.Sources = sources
		if len(g.Nodes) > 0 {
			meta.URL = g.Nodes[path[0]].URL
		}
		EnrichWithTaxonomy(&meta)
		meta.Confidence = conf
		meta.Tier = TierForScore(conf)
		out = append(out, meta)
	}
	return out
}

// SynthesizeAttackPaths builds the finding graph and converts maximal
// attack-flow walks into correlated meta-findings. It is the pipeline entry
// point used by both the legacy enrichment and the active-check engine.
func SynthesizeAttackPaths(findings []Finding) []Finding {
	g := BuildFindingGraph(findings)
	return SynthesizeAttackPathFindings(g, g.AttackPaths(4))
}

// promoteSeverity raises a severity one level, capped at Critical.
func promoteSeverity(s Severity) Severity {
	switch s {
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	case SeverityHigh:
		return SeverityCritical
	default:
		return SeverityCritical
	}
}
