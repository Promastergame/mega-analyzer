package sandbox

import (
	"context"
	"testing"
	"time"
)

// BenchmarkKernelMonitorEventThroughput benchmarks kernel monitor event processing throughput.
//
// Validates: Requirement 10.1
func BenchmarkKernelMonitorEventThroughput(b *testing.B) {
	monitor := NewKernelMonitor()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := monitor.Start(ctx); err != nil {
		b.Skipf("Kernel monitor start failed (expected on non-Windows): %v", err)
	}
	defer monitor.Stop()

	// Measure event processing throughput
	b.ResetTimer()
	eventCount := 0

	for i := 0; i < b.N; i++ {
		select {
		case <-monitor.Events():
			eventCount++
		case <-time.After(100 * time.Millisecond):
			// No more events
			b.StopTimer()
			return
		}
	}

	b.ReportMetric(float64(eventCount)/b.Elapsed().Seconds(), "events/sec")
}

// BenchmarkAPITracerOverhead benchmarks API tracer overhead.
//
// Validates: Requirement 10.4
func BenchmarkAPITracerOverhead(b *testing.B) {
	tracer := NewAPITracer([]string{CategoryMemory, CategoryProcess})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tracer.Attach(ctx, 1234); err != nil {
		b.Skipf("API tracer attach failed (expected on non-Windows): %v", err)
	}
	defer tracer.Stop()

	// Measure API call logging overhead
	b.ResetTimer()
	callCount := 0

	for i := 0; i < b.N; i++ {
		select {
		case <-tracer.Calls():
			callCount++
		case <-time.After(100 * time.Millisecond):
			// No more calls
			b.StopTimer()
			return
		}
	}

	b.ReportMetric(float64(callCount)/b.Elapsed().Seconds(), "calls/sec")
}

// BenchmarkBehaviorClassifierAnalysis benchmarks behavior analysis performance.
func BenchmarkBehaviorClassifierAnalysis(b *testing.B) {
	classifier := NewBehaviorClassifier()

	// Create test events
	events := make([]Event, 1000)
	baseTime := time.Now()
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			events[i] = KernelEvent{
				Timestamp: baseTime.Add(time.Duration(i) * time.Millisecond),
				EventType: EventRegSetValue,
				ProcessID: 1234,
				Path:      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Test",
			}
		} else {
			events[i] = APICall{
				Timestamp: baseTime.Add(time.Duration(i) * time.Millisecond),
				ProcessID: 1234,
				Function:  "VirtualAllocEx",
			}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = classifier.Analyze(events)
	}
}

// BenchmarkVisualGeneratorProcessGraph benchmarks process graph generation.
func BenchmarkVisualGeneratorProcessGraph(b *testing.B) {
	generator := NewVisualGenerator()

	// Create test processes
	processes := []ObservedProcess{
		{PID: 1000, ParentPID: 0, Name: "parent.exe"},
		{PID: 1001, ParentPID: 1000, Name: "child1.exe"},
		{PID: 1002, ParentPID: 1000, Name: "child2.exe"},
		{PID: 1003, ParentPID: 1001, Name: "grandchild.exe"},
	}

	behaviors := []BehaviorIndicator{
		{ProcessID: 1001, Type: "Process Injection", Severity: 9},
		{ProcessID: 1002, Type: "Registry Persistence", Severity: 7},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateProcessGraph(processes, behaviors)
		if err != nil {
			b.Fatalf("Process graph generation failed: %v", err)
		}
	}
}

// BenchmarkVisualGeneratorTimeline benchmarks timeline generation.
func BenchmarkVisualGeneratorTimeline(b *testing.B) {
	generator := NewVisualGenerator()

	// Create test events
	events := make([]Event, 100)
	baseTime := time.Now()
	for i := 0; i < 100; i++ {
		events[i] = KernelEvent{
			Timestamp: baseTime.Add(time.Duration(i) * time.Millisecond),
			EventType: EventFileCreate,
			ProcessID: 1234,
			Path:      "C:\\temp\\file.txt",
		}
	}

	behaviors := []BehaviorIndicator{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateTimeline(events, behaviors)
		if err != nil {
			b.Fatalf("Timeline generation failed: %v", err)
		}
	}
}

// BenchmarkMemoryUsage benchmarks memory usage under load.
//
// Validates: Requirement 10.3
func BenchmarkMemoryUsage(b *testing.B) {
	// Create components
	kernelEvents := make([]KernelEvent, 0, MaxKernelEvents)
	apiCalls := make([]APICall, 0, MaxAPICalls)

	baseTime := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate event collection up to limits
		if len(kernelEvents) < MaxKernelEvents {
			kernelEvents = append(kernelEvents, KernelEvent{
				Timestamp: baseTime.Add(time.Duration(i) * time.Millisecond),
				EventType: EventFileCreate,
				ProcessID: 1234,
				Path:      "C:\\temp\\file.txt",
			})
		}

		if len(apiCalls) < MaxAPICalls {
			apiCalls = append(apiCalls, APICall{
				Timestamp: baseTime.Add(time.Duration(i) * time.Millisecond),
				ProcessID: 1234,
				Function:  "VirtualAllocEx",
			})
		}
	}

	// Report memory usage estimate
	kernelEventSize := len(kernelEvents) * 500 // ~500 bytes per event
	apiCallSize := len(apiCalls) * 1024        // ~1 KB per call
	totalMB := (kernelEventSize + apiCallSize) / (1024 * 1024)

	b.ReportMetric(float64(totalMB), "MB")
}
