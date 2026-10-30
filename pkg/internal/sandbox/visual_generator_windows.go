//go:build windows

package sandbox

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// windowsVisualGenerator implements VisualGenerator for Windows.
type windowsVisualGenerator struct{}

func newVisualGenerator() VisualGenerator {
	return &windowsVisualGenerator{}
}

// GenerateProcessGraph creates a DOT format process tree.
//
// Validates: Requirements 5.1, 5.3
func (vg *windowsVisualGenerator) GenerateProcessGraph(processes []ObservedProcess, behaviors []BehaviorIndicator) (string, error) {
	// Build process tree
	roots := BuildProcessTree(processes)

	// Annotate with behaviors
	AnnotateProcessTree(roots, behaviors)

	// Generate DOT format
	var sb strings.Builder
	sb.WriteString("digraph ProcessTree {\n")
	sb.WriteString("  rankdir=TB;\n")
	sb.WriteString("  node [shape=box, style=filled];\n\n")

	// Track visited nodes to avoid duplicates
	visited := make(map[int]bool)

	// Recursively generate nodes and edges
	var generateNode func(node *ProcessGraphNode)
	generateNode = func(node *ProcessGraphNode) {
		if visited[node.PID] {
			return
		}
		visited[node.PID] = true

		// Determine node color based on behaviors
		color := "#ffffff"
		if len(node.Behaviors) > 0 {
			// Has suspicious behaviors
			color = "#ffcccc"
			for _, behavior := range node.Behaviors {
				if strings.Contains(behavior, "Injection") || strings.Contains(behavior, "Ransomware") {
					color = "#ff8888"
					break
				}
			}
		}

		// Generate node
		label := fmt.Sprintf("%s\\nPID: %d", escapeLabel(node.Name), node.PID)
		if len(node.Behaviors) > 0 {
			label += "\\n" + strings.Join(node.Behaviors, ", ")
		}

		sb.WriteString(fmt.Sprintf("  p%d [label=\"%s\", fillcolor=\"%s\"];\n", node.PID, label, color))

		// Generate edges to children
		for _, child := range node.Children {
			sb.WriteString(fmt.Sprintf("  p%d -> p%d;\n", node.PID, child.PID))
			generateNode(child)
		}
	}

	for _, root := range roots {
		generateNode(root)
	}

	sb.WriteString("}\n")

	return sb.String(), nil
}

// GenerateTimeline creates an HTML/SVG timeline of events.
//
// Validates: Requirements 5.2, 5.4
func (vg *windowsVisualGenerator) GenerateTimeline(events []Event, behaviors []BehaviorIndicator) (string, error) {
	if len(events) == 0 {
		return "<html><body><p>No events to display</p></body></html>", nil
	}

	// Convert events to timeline events
	timelineEvents := []TimelineEvent{}
	for _, event := range events {
		track := GetEventTrack(event)
		eventType := event.GetEventType()
		severity := 1

		// Check if this event is associated with a behavior
		for _, behavior := range behaviors {
			if behavior.ProcessID == event.GetProcessID() &&
				event.GetTimestamp().Sub(behavior.Timestamp).Abs() < 1*time.Second {
				severity = behavior.Severity
				break
			}
		}

		color := GetEventColor(eventType, severity)

		timelineEvents = append(timelineEvents, TimelineEvent{
			Timestamp:   event.GetTimestamp().Format("15:04:05.000"),
			Track:       track,
			Type:        eventType,
			Description: fmt.Sprintf("PID %d: %s", event.GetProcessID(), eventType),
			Severity:    severity,
			Color:       color,
		})
	}

	// Generate HTML
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html>\n")
	sb.WriteString("<html>\n<head>\n")
	sb.WriteString("<title>Sandbox Timeline</title>\n")
	sb.WriteString("<style>\n")
	sb.WriteString("body { font-family: Arial, sans-serif; margin: 20px; }\n")
	sb.WriteString("table { border-collapse: collapse; width: 100%; }\n")
	sb.WriteString("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
	sb.WriteString("th { background-color: #4CAF50; color: white; }\n")
	sb.WriteString("tr:nth-child(even) { background-color: #f2f2f2; }\n")
	sb.WriteString(".severity-high { background-color: #ffcccc; }\n")
	sb.WriteString(".severity-medium { background-color: #ffffcc; }\n")
	sb.WriteString("</style>\n")
	sb.WriteString("</head>\n<body>\n")
	sb.WriteString("<h1>Sandbox Timeline</h1>\n")
	sb.WriteString("<table>\n")
	sb.WriteString("<tr><th>Timestamp</th><th>Track</th><th>Type</th><th>Description</th><th>Severity</th></tr>\n")

	for _, event := range timelineEvents {
		rowClass := ""
		if event.Severity >= 8 {
			rowClass = " class=\"severity-high\""
		} else if event.Severity >= 5 {
			rowClass = " class=\"severity-medium\""
		}

		sb.WriteString(fmt.Sprintf("<tr%s><td>%s</td><td>%s</td><td style=\"color: %s\">%s</td><td>%s</td><td>%d</td></tr>\n",
			rowClass,
			event.Timestamp,
			event.Track,
			event.Color,
			escapeHTML(event.Type),
			escapeHTML(event.Description),
			event.Severity))
	}

	sb.WriteString("</table>\n")
	sb.WriteString("</body>\n</html>\n")

	return sb.String(), nil
}

// ExportDOT exports the process graph to a DOT file.
func (vg *windowsVisualGenerator) ExportDOT(outputPath string, graph string) error {
	return os.WriteFile(outputPath, []byte(graph), 0644)
}

// ExportHTML exports the timeline to an HTML file.
func (vg *windowsVisualGenerator) ExportHTML(outputPath string, timeline string) error {
	return os.WriteFile(outputPath, []byte(timeline), 0644)
}

// escapeLabel escapes special characters for DOT labels.
func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// escapeHTML escapes special characters for HTML.
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
