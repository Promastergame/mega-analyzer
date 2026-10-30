package cfg

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CFG VISUALIZER
// ═══════════════════════════════════════════════════════════════════════════════

type Visualizer struct {
	cfg *ControlFlowGraph
}

func NewVisualizer(cfg *ControlFlowGraph) *Visualizer {
	return &Visualizer{cfg: cfg}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOT (GRAPHVIZ) EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

type DOTOptions struct {
	ShowInstructions bool
	ShowConditions   bool
	ShowMetrics      bool
	Compact          bool
	ColorScheme      string // "dark", "light", "mono"
}

func DefaultDOTOptions() DOTOptions {
	return DOTOptions{
		ShowInstructions: false,
		ShowConditions:   true,
		ShowMetrics:      true,
		Compact:          false,
		ColorScheme:      "dark",
	}
}

func (v *Visualizer) ExportDOT(opts DOTOptions) string {
	var sb strings.Builder

	// Header
	sb.WriteString("digraph CFG {\n")
	sb.WriteString("  rankdir=TB;\n")
	sb.WriteString("  node [shape=box, fontname=\"Helvetica\", fontsize=10];\n")
	sb.WriteString("  edge [fontname=\"Helvetica\", fontsize=9];\n")

	// Graph attributes
	if opts.ColorScheme == "dark" {
		sb.WriteString("  bgcolor=\"#1e1e1e\";\n")
		sb.WriteString("  node [style=filled, fillcolor=\"#2d2d2d\", fontcolor=\"#d4d4d4\"];\n")
		sb.WriteString("  edge [color=\"#808080\"];\n")
	}

	sb.WriteString("\n")

	// Nodes
	for _, node := range v.cfg.Nodes {
		v.writeDOTNode(&sb, node, opts)
	}

	sb.WriteString("\n")

	// Edges
	for _, edge := range v.cfg.Edges {
		v.writeDOTEdge(&sb, edge, opts)
	}

	sb.WriteString("}\n")

	return sb.String()
}

func (v *Visualizer) writeDOTNode(sb *strings.Builder, node *CFGNode, opts DOTOptions) {
	label := v.buildNodeLabel(node, opts)
	attrs := v.buildNodeAttrs(node, opts)

	sb.WriteString(fmt.Sprintf("  N%d [label=%s%s];\n",
		node.ID, quote(label), attrs))
}

func (v *Visualizer) buildNodeLabel(node *CFGNode, opts DOTOptions) string {
	var parts []string

	// Node ID and type
	parts = append(parts, fmt.Sprintf("N%d [%s]", node.ID, node.Type))

	// Line range
	if !opts.Compact {
		parts = append(parts, fmt.Sprintf("L%d-%d", node.LineStart, node.LineEnd))
	}

	// Condition
	if opts.ShowConditions && node.Condition != nil {
		cond := fmt.Sprintf("%s %s", node.Condition.Register1, node.Condition.Op)
		if !node.Condition.Op.IsZeroCheck() {
			cond += " " + node.Condition.Register2
		}
		parts = append(parts, cond)
	}

	// Instructions
	if opts.ShowInstructions && len(node.Instructions) > 0 {
		for i, instr := range node.Instructions {
			if i >= 3 {
				parts = append(parts, "...")
				break
			}
			parts = append(parts, instr.Opcode)
		}
	}

	// Metrics
	if opts.ShowMetrics {
		if node.LoopDepth > 0 {
			parts = append(parts, fmt.Sprintf("loop:%d", node.LoopDepth))
		}
		if node.IsGuard {
			parts = append(parts, "GUARD")
		}
		if node.IsFunnel && node.FunnelInfo != nil {
			parts = append(parts, fmt.Sprintf("funnel:%d", len(node.FunnelInfo.Conditions)))
		}
	}

	return strings.Join(parts, "\\n")
}

func (v *Visualizer) buildNodeAttrs(node *CFGNode, opts DOTOptions) string {
	var attrs []string

	// Colors by type
	colors := map[NodeType]string{
		NodeTypeEntry:     "#4CAF50", // Green
		NodeTypeCondition: "#2196F3", // Blue
		NodeTypeSwitch:    "#9C27B0", // Purple
		NodeTypeReturn:    "#FF9800", // Orange
		NodeTypeThrow:     "#F44336", // Red
		NodeTypeExit:      "#FF9800", // Orange
		NodeTypeCatch:     "#795548", // Brown
		NodeTypeGuard:     "#00BCD4", // Cyan
		NodeTypeFunnel:    "#E91E63", // Pink
	}

	if color, ok := colors[node.Type]; ok && opts.ColorScheme != "mono" {
		attrs = append(attrs, fmt.Sprintf("fillcolor=\"%s\"", color))
		attrs = append(attrs, "fontcolor=\"white\"")
	}

	// Special shapes
	switch node.Type {
	case NodeTypeCondition, NodeTypeGuard:
		attrs = append(attrs, "shape=diamond")
	case NodeTypeSwitch:
		attrs = append(attrs, "shape=hexagon")
	case NodeTypeEntry:
		attrs = append(attrs, "shape=ellipse")
		attrs = append(attrs, "penwidth=2")
	case NodeTypeReturn, NodeTypeExit:
		attrs = append(attrs, "shape=ellipse")
		attrs = append(attrs, "style=\"filled,bold\"")
	}

	if len(attrs) == 0 {
		return ""
	}

	return ", " + strings.Join(attrs, ", ")
}

func (v *Visualizer) writeDOTEdge(sb *strings.Builder, edge *CFGEdge, opts DOTOptions) {
	attrs := v.buildEdgeAttrs(edge, opts)

	sb.WriteString(fmt.Sprintf("  N%d -> N%d%s;\n",
		edge.From.ID, edge.To.ID, attrs))
}

func (v *Visualizer) buildEdgeAttrs(edge *CFGEdge, _ DOTOptions) string {
	var attrs []string

	// Labels
	switch edge.Type {
	case EdgeTrue:
		attrs = append(attrs, "label=\"T\"", "color=\"#4CAF50\"")
	case EdgeFalse:
		attrs = append(attrs, "label=\"F\"", "color=\"#F44336\"")
	case EdgeGoto:
		attrs = append(attrs, "style=dashed")
	case EdgeException:
		attrs = append(attrs, "label=\"ex\"", "color=\"#795548\"", "style=dotted")
	case EdgeSwitch:
		if edge.Label != "" {
			attrs = append(attrs, fmt.Sprintf("label=\"%s\"", edge.Label))
		}
	}

	if len(attrs) == 0 {
		return ""
	}

	return " [" + strings.Join(attrs, ", ") + "]"
}

// ═══════════════════════════════════════════════════════════════════════════════
// ASCII VISUALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

func (v *Visualizer) ExportASCII() string {
	var sb strings.Builder

	sb.WriteString("Control Flow Graph\n")
	sb.WriteString(strings.Repeat("═", 50) + "\n\n")

	// Summary
	sb.WriteString(fmt.Sprintf("Nodes: %d | Edges: %d | Exits: %d\n\n",
		len(v.cfg.Nodes), len(v.cfg.Edges), len(v.cfg.Exits)))

	// Nodes
	for _, node := range v.cfg.Nodes {
		v.writeASCIINode(&sb, node)
	}

	return sb.String()
}

func (v *Visualizer) writeASCIINode(sb *strings.Builder, node *CFGNode) {
	// Node header
	typeIcon := v.getNodeIcon(node.Type)
	sb.WriteString(fmt.Sprintf("%s [%d] %s (L%d-%d)\n",
		typeIcon, node.ID, node.Type, node.LineStart, node.LineEnd))

	// Condition
	if node.Condition != nil {
		sb.WriteString(fmt.Sprintf("   ├─ Cond: %s %s",
			node.Condition.Register1, node.Condition.Op))
		if !node.Condition.Op.IsZeroCheck() {
			sb.WriteString(" " + node.Condition.Register2)
		}
		sb.WriteString("\n")
	}

	// Successors
	if len(node.Successors) > 0 {
		for i, succ := range node.Successors {
			prefix := "├──"
			if i == len(node.Successors)-1 {
				prefix = "└──"
			}

			edgeType := ""
			if edge := v.cfg.FindEdge(node, succ); edge != nil {
				edgeType = fmt.Sprintf(" [%s]", edge.Type)
			}

			sb.WriteString(fmt.Sprintf("   %s → N%d%s\n", prefix, succ.ID, edgeType))
		}
	} else {
		sb.WriteString("   └── (no successors)\n")
	}

	sb.WriteString("\n")
}

func (v *Visualizer) getNodeIcon(t NodeType) string {
	icons := map[NodeType]string{
		NodeTypeEntry:     "🟢",
		NodeTypeBasic:     "⬜",
		NodeTypeCondition: "🔷",
		NodeTypeSwitch:    "🔶",
		NodeTypeReturn:    "🔴",
		NodeTypeThrow:     "💥",
		NodeTypeExit:      "🔴",
		NodeTypeCatch:     "🟤",
		NodeTypeGuard:     "🛡️",
		NodeTypeFunnel:    "🔻",
	}

	if icon, ok := icons[t]; ok {
		return icon
	}
	return "⬜"
}

func quote(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}
