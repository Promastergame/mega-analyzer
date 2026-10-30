//go:build !windows

package sandbox

import "fmt"

// stubVisualGenerator is a no-op implementation for non-Windows platforms.
type stubVisualGenerator struct{}

func newVisualGenerator() VisualGenerator {
	return &stubVisualGenerator{}
}

func (vg *stubVisualGenerator) GenerateProcessGraph(processes []ObservedProcess, behaviors []BehaviorIndicator) (string, error) {
	return "", fmt.Errorf("visual generation is only supported on Windows")
}

func (vg *stubVisualGenerator) GenerateTimeline(events []Event, behaviors []BehaviorIndicator) (string, error) {
	return "", fmt.Errorf("visual generation is only supported on Windows")
}

func (vg *stubVisualGenerator) ExportDOT(outputPath string, graph string) error {
	return fmt.Errorf("visual generation is only supported on Windows")
}

func (vg *stubVisualGenerator) ExportHTML(outputPath string, timeline string) error {
	return fmt.Errorf("visual generation is only supported on Windows")
}
