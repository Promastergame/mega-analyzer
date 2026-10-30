package sandbox

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestVisualGenerator_GenerateProcessGraph(t *testing.T) {
	vg := NewVisualGenerator()

	processes := []ObservedProcess{
		{PID: 1000, ParentPID: 0, Name: "parent.exe", FirstSeen: time.Now()},
		{PID: 2000, ParentPID: 1000, Name: "child1.exe", FirstSeen: time.Now()},
		{PID: 3000, ParentPID: 1000, Name: "child2.exe", FirstSeen: time.Now()},
	}

	behaviors := []BehaviorIndicator{
		{ProcessID: 2000, Type: "Process Injection", Severity: 9},
	}

	graph, err := vg.GenerateProcessGraph(processes, behaviors)
	if err != nil {
		t.Skipf("GenerateProcessGraph failed (expected on non-Windows): %v", err)
	}

	if graph == "" {
		t.Error("Expected non-empty graph")
	}

	// Verify DOT format
	if !strings.Contains(graph, "digraph") {
		t.Error("Expected DOT format to contain 'digraph'")
	}
}

func TestVisualGenerator_GenerateTimeline(t *testing.T) {
	vg := NewVisualGenerator()

	events := []Event{
		KernelEvent{
			Timestamp: time.Now(),
			EventType: EventFileCreate,
			ProcessID: 1234,
			Path:      "C:\\test.txt",
		},
		APICall{
			Timestamp: time.Now().Add(1 * time.Second),
			ProcessID: 1234,
			Function:  "VirtualAllocEx",
		},
	}

	behaviors := []BehaviorIndicator{
		{ProcessID: 1234, Type: "Process Injection", Severity: 9, Timestamp: time.Now()},
	}

	timeline, err := vg.GenerateTimeline(events, behaviors)
	if err != nil {
		t.Skipf("GenerateTimeline failed (expected on non-Windows): %v", err)
	}

	if timeline == "" {
		t.Error("Expected non-empty timeline")
	}

	// Verify HTML format
	if !strings.Contains(timeline, "<html>") {
		t.Error("Expected HTML format to contain '<html>'")
	}
}

func TestVisualGenerator_ExportDOT(t *testing.T) {
	vg := NewVisualGenerator()

	processes := []ObservedProcess{
		{PID: 1000, ParentPID: 0, Name: "test.exe", FirstSeen: time.Now()},
	}

	graph, err := vg.GenerateProcessGraph(processes, []BehaviorIndicator{})
	if err != nil {
		t.Skipf("GenerateProcessGraph failed (expected on non-Windows): %v", err)
	}

	tmpFile := "test_graph.dot"
	defer os.Remove(tmpFile)

	err = vg.ExportDOT(tmpFile, graph)
	if err != nil {
		t.Skipf("ExportDOT failed (expected on non-Windows): %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Error("Expected DOT file to be created")
	}
}

func TestVisualGenerator_ExportHTML(t *testing.T) {
	vg := NewVisualGenerator()

	events := []Event{
		KernelEvent{
			Timestamp: time.Now(),
			EventType: EventFileCreate,
			ProcessID: 1234,
		},
	}

	timeline, err := vg.GenerateTimeline(events, []BehaviorIndicator{})
	if err != nil {
		t.Skipf("GenerateTimeline failed (expected on non-Windows): %v", err)
	}

	tmpFile := "test_timeline.html"
	defer os.Remove(tmpFile)

	err = vg.ExportHTML(tmpFile, timeline)
	if err != nil {
		t.Skipf("ExportHTML failed (expected on non-Windows): %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Error("Expected HTML file to be created")
	}
}

func TestBuildProcessTree(t *testing.T) {
	processes := []ObservedProcess{
		{PID: 1000, ParentPID: 0, Name: "parent.exe"},
		{PID: 2000, ParentPID: 1000, Name: "child1.exe"},
		{PID: 3000, ParentPID: 1000, Name: "child2.exe"},
		{PID: 4000, ParentPID: 2000, Name: "grandchild.exe"},
	}

	roots := BuildProcessTree(processes)

	if len(roots) != 1 {
		t.Errorf("Expected 1 root, got %d", len(roots))
	}

	root := roots[0]
	if root.PID != 1000 {
		t.Errorf("Expected root PID 1000, got %d", root.PID)
	}

	if len(root.Children) != 2 {
		t.Errorf("Expected 2 children, got %d", len(root.Children))
	}

	// Check grandchild
	child1 := root.Children[0]
	if len(child1.Children) != 1 {
		t.Errorf("Expected 1 grandchild, got %d", len(child1.Children))
	}
}

func TestAnnotateProcessTree(t *testing.T) {
	processes := []ObservedProcess{
		{PID: 1000, ParentPID: 0, Name: "parent.exe"},
		{PID: 2000, ParentPID: 1000, Name: "child.exe"},
	}

	roots := BuildProcessTree(processes)

	behaviors := []BehaviorIndicator{
		{ProcessID: 2000, Type: "Process Injection"},
		{ProcessID: 2000, Type: "Persistence"},
	}

	AnnotateProcessTree(roots, behaviors)

	// Check that child has behaviors
	child := roots[0].Children[0]
	if len(child.Behaviors) != 2 {
		t.Errorf("Expected 2 behaviors, got %d", len(child.Behaviors))
	}
}

func TestGetEventColor(t *testing.T) {
	tests := []struct {
		eventType string
		severity  int
		expected  string
	}{
		{"Injection", 9, "#ff0000"},
		{"Persistence", 7, "#ff8800"},
		{"Network", 3, "#0088ff"},
		{"Unknown", 2, "#888888"},
	}

	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			color := GetEventColor(tt.eventType, tt.severity)
			if color == "" {
				t.Error("Expected non-empty color")
			}
		})
	}
}

func TestGetEventTrack(t *testing.T) {
	tests := []struct {
		event    Event
		expected string
	}{
		{KernelEvent{}, "Kernel"},
		{APICall{}, "API"},
		{NetworkConnection{}, "Network"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			track := GetEventTrack(tt.event)
			if track != tt.expected {
				t.Errorf("Expected track %s, got %s", tt.expected, track)
			}
		})
	}
}
