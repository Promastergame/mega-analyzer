package sandbox

// VisualGenerator creates visual representations of process trees,
// event timelines, and behavior flows.
//
// Validates: Requirements 5.1, 5.2, 5.3, 5.4
type VisualGenerator interface {
	// GenerateProcessGraph creates a DOT format process tree
	GenerateProcessGraph(processes []ObservedProcess, behaviors []BehaviorIndicator) (string, error)

	// GenerateTimeline creates an HTML/SVG timeline of events
	GenerateTimeline(events []Event, behaviors []BehaviorIndicator) (string, error)

	// ExportDOT exports the process graph to a DOT file
	ExportDOT(outputPath string, graph string) error

	// ExportHTML exports the timeline to an HTML file
	ExportHTML(outputPath string, timeline string) error
}

// NewVisualGenerator creates a new visual generator.
func NewVisualGenerator() VisualGenerator {
	return newVisualGenerator()
}

// ProcessGraphNode represents a node in the process graph.
type ProcessGraphNode struct {
	PID            int
	Name           string
	CommandLine    string
	IntegrityLevel string
	Behaviors      []string
	Children       []*ProcessGraphNode
}

// TimelineEvent represents an event in the timeline.
type TimelineEvent struct {
	Timestamp   string
	Track       string // Kernel, API, Network, etc.
	Type        string
	Description string
	Severity    int
	Color       string
}

// BuildProcessTree builds a tree structure from a flat list of processes.
func BuildProcessTree(processes []ObservedProcess) []*ProcessGraphNode {
	// Create a map of PID to node
	nodes := make(map[int]*ProcessGraphNode)
	for _, proc := range processes {
		nodes[proc.PID] = &ProcessGraphNode{
			PID:         proc.PID,
			Name:        proc.Name,
			CommandLine: proc.CommandLine,
			Behaviors:   []string{},
			Children:    []*ProcessGraphNode{},
		}
	}

	// Build parent-child relationships
	roots := []*ProcessGraphNode{}
	for _, proc := range processes {
		node := nodes[proc.PID]
		if proc.ParentPID == 0 || nodes[proc.ParentPID] == nil {
			// Root process
			roots = append(roots, node)
		} else {
			// Child process
			parent := nodes[proc.ParentPID]
			parent.Children = append(parent.Children, node)
		}
	}

	return roots
}

// AnnotateProcessTree adds behavior annotations to process nodes.
func AnnotateProcessTree(roots []*ProcessGraphNode, behaviors []BehaviorIndicator) {
	// Create a map of PID to behaviors
	behaviorMap := make(map[int][]string)
	for _, behavior := range behaviors {
		behaviorMap[behavior.ProcessID] = append(behaviorMap[behavior.ProcessID], behavior.Type)
	}

	// Recursively annotate nodes
	var annotate func(node *ProcessGraphNode)
	annotate = func(node *ProcessGraphNode) {
		if behaviors, ok := behaviorMap[node.PID]; ok {
			node.Behaviors = behaviors
		}
		for _, child := range node.Children {
			annotate(child)
		}
	}

	for _, root := range roots {
		annotate(root)
	}
}

// GetEventColor returns a color for an event based on its type.
func GetEventColor(eventType string, severity int) string {
	// High severity events
	if severity >= 8 {
		return "#ff0000" // Red
	}

	// Medium severity events
	if severity >= 5 {
		return "#ff8800" // Orange
	}

	// Event type specific colors
	switch eventType {
	case "Injection":
		return "#ff0000" // Red
	case "Persistence":
		return "#ff8800" // Orange
	case "Data Exfiltration":
		return "#ff00ff" // Magenta
	case "Network":
		return "#0088ff" // Blue
	case "File":
		return "#00ff00" // Green
	case "Registry":
		return "#ffff00" // Yellow
	default:
		return "#888888" // Gray
	}
}

// GetEventTrack returns the track name for an event.
func GetEventTrack(event Event) string {
	switch e := event.(type) {
	case KernelEvent:
		return "Kernel"
	case APICall:
		return "API"
	case NetworkConnection:
		return "Network"
	default:
		_ = e
		return "Other"
	}
}
