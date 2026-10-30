//go:build windows

package sandbox

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// windowsEnhancedComponents holds all Windows-native enhancement components.
type windowsEnhancedComponents struct {
	kernelMonitor       KernelMonitor
	vssManager          VSSManager
	wfpMonitor          WFPMonitor
	apiTracer           APITracer
	timeManipulator     TimeManipulator
	behaviorClassifier  BehaviorClassifier
	antiSandboxDetector AntiSandboxDetector
	visualGenerator     VisualGenerator

	baselineSnapshot *Snapshot
	finalSnapshot    *Snapshot

	kernelEvents       []KernelEvent
	apiCalls           []APICall
	startedComponents  []string
	degradedComponents []ComponentStatus

	apiCollectorDone chan struct{}
	mu               sync.Mutex
}

var checkPrivilegesFunc = checkPrivileges

// initializeEnhancedComponents creates and initializes all Windows-native components.
func initializeEnhancedComponents(cfg Config) (*windowsEnhancedComponents, error) {
	components := &windowsEnhancedComponents{
		kernelEvents: []KernelEvent{},
		apiCalls:     []APICall{},
	}
	// Offline classification and report generation do not need elevation.
	// Degrade only the requested collectors that require it.
	var privilegeErr error
	if cfg.EnableKernelMonitor || cfg.EnableVSS || cfg.EnableWFP {
		if err := checkPrivilegesFunc(); err != nil {
			privilegeErr = fmt.Errorf("requested privileged Windows collectors are unavailable: %w", err)
			for _, component := range []struct {
				name    string
				enabled bool
			}{{"kernel_monitor", cfg.EnableKernelMonitor}, {"vss", cfg.EnableVSS}, {"wfp", cfg.EnableWFP}} {
				if component.enabled {
					components.addDegraded(component.name, "init", privilegeErr)
				}
			}
		}
	}

	// Initialize components based on config
	if cfg.EnableKernelMonitor && privilegeErr == nil {
		components.kernelMonitor = NewKernelMonitor()
	}

	if cfg.EnableVSS && privilegeErr == nil {
		components.vssManager = NewVSSManager()
	}

	if cfg.EnableWFP && privilegeErr == nil {
		components.wfpMonitor = NewWFPMonitor()
	}

	if cfg.EnableAPITracing {
		components.apiTracer = NewAPITracer(cfg.APITraceCategories)
	}

	if cfg.EnableTimeManip {
		components.timeManipulator = NewTimeManipulator()
	}

	// Always initialize behavior classifier and anti-sandbox detector
	components.behaviorClassifier = NewBehaviorClassifier()
	components.antiSandboxDetector = NewAntiSandboxDetector()
	components.visualGenerator = NewVisualGenerator()

	return components, privilegeErr
}

// startComponents starts all enabled components before execution.
// When called from Run() in sandbox.go, rootPID is created with CREATE_SUSPENDED
// and has not yet been resumed, so apiTracer.Attach installs user-mode hooks
// before the sample's entry point or TLS callbacks execute.
func (c *windowsEnhancedComponents) startComponents(ctx context.Context, cfg Config, rootPID int) error {
	var startErrors []error

	// Start kernel monitor
	if c.kernelMonitor != nil {
		if err := c.kernelMonitor.Start(ctx); err != nil {
			startErrors = append(startErrors, fmt.Errorf("kernel monitor start failed: %w", err))
			c.addDegraded("kernel_monitor", "start", err)
		} else {
			c.addStarted("kernel_monitor")
			// This collector reads a real external pipe. Without a driver,
			// Start fails; successful reads must not be labelled synthetic.
			// Start goroutine to collect kernel events
			go c.collectKernelEvents(ctx)
		}
	}

	// Create baseline VSS snapshot
	if c.vssManager != nil {
		snapshot, err := c.vssManager.CreateSnapshot(ctx, "C:\\")
		if err != nil {
			startErrors = append(startErrors, fmt.Errorf("baseline snapshot failed: %w", err))
			// vssadmin create shadow is Server-only, so this always fails on Windows
			// 10 and 11 client, which is what analysts actually run. Say that rather
			// than surfacing a bare COM error.
			c.addDegraded("vss", "baseline", fmt.Errorf("%w (vssadmin create shadow is Server-only; unavailable on Windows client editions)", err))
		} else {
			c.addStarted("vss")
			c.baselineSnapshot = snapshot
		}
	}

	// Start WFP monitor
	if c.wfpMonitor != nil {
		if err := c.wfpMonitor.Start(ctx, []int{rootPID}); err != nil {
			startErrors = append(startErrors, fmt.Errorf("wfp monitor start failed: %w", err))
			c.addDegraded("wfp", "start", err)
		} else {
			c.addStarted("wfp")
			c.addSynthetic("wfp",
				"ETW event consumption is not implemented; mock fallback generates sample traffic")
		}
	}

	// Attach API tracer to root process before process resume.
	// Real observed events from a working APITracer backend must NEVER be
	// marked synthetic.
	if c.apiTracer != nil {
		if err := c.apiTracer.Attach(ctx, rootPID); err != nil {
			startErrors = append(startErrors, fmt.Errorf("api tracer attach failed: %w", err))
			c.addDegraded("api_tracing", "attach", err)
		} else {
			c.addStarted("api_tracing")
			doneCh := make(chan struct{})
			c.mu.Lock()
			c.apiCollectorDone = doneCh
			c.mu.Unlock()
			// Start goroutine to collect API calls
			go c.collectAPICalls(ctx, doneCh)
		}
		c.syncAPITracerDiagnostics()
	}

	// Enable time manipulation
	if c.timeManipulator != nil {
		if err := c.timeManipulator.Enable(cfg.TimeScaleFactor); err != nil {
			startErrors = append(startErrors, fmt.Errorf("time manipulator enable failed: %w", err))
			c.addDegraded("time_manipulation", "enable", err)
		} else {
			c.addStarted("time_manipulation")
		}
	}

	if len(startErrors) > 0 {
		// Return first error but continue with other components
		return startErrors[0]
	}

	return nil
}

// FollowChildProcess attaches the active APITracer to a newly discovered child
// process PID, surfacing any attach failure in degradedComponents.
func (c *windowsEnhancedComponents) FollowChildProcess(ctx context.Context, childPID int) {
	if c.apiTracer == nil || childPID <= 0 {
		return
	}
	c.mu.Lock()
	synthetic := c.isSynthetic("api_tracing")
	c.mu.Unlock()
	if synthetic {
		return
	}
	if err := c.apiTracer.Attach(ctx, childPID); err != nil {
		c.addDegraded("api_tracing", "child_attach", fmt.Errorf("child PID %d: %w", childPID, err))
	}
	c.syncAPITracerDiagnostics()
}

func (c *windowsEnhancedComponents) syncAPITracerDiagnostics() {
	provider, ok := c.apiTracer.(apiTracerStatusProvider)
	if !ok {
		return
	}
	statuses := provider.DegradedStatuses()
	if len(statuses) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range statuses {
		exists := false
		for _, cur := range c.degradedComponents {
			if cur.Name == st.Name && cur.Phase == st.Phase && cur.Reason == st.Reason {
				exists = true
				break
			}
		}
		if !exists {
			c.degradedComponents = append(c.degradedComponents, st)
		}
	}
}

func (c *windowsEnhancedComponents) addStarted(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.startedComponents {
		if existing == name {
			return
		}
	}
	c.startedComponents = append(c.startedComponents, name)
}

// addSynthetic records a component that started but whose data is generated
// rather than observed.
//
// Only mark a source whose implementation generates sample data. A missing
// backend belongs in addDegraded, and successful external pipe reads are not
// synthetic. Consumers must exclude explicitly synthetic data from evidence.
func (c *windowsEnhancedComponents) addSynthetic(name, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.degradedComponents = append(c.degradedComponents, ComponentStatus{
		Name:   name,
		Phase:  "synthetic",
		Reason: reason,
	})
}

func (c *windowsEnhancedComponents) addDegraded(name, phase string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reason := err.Error()
	for _, existing := range c.degradedComponents {
		if existing.Name == name && existing.Phase == phase && existing.Reason == reason {
			return
		}
	}
	c.degradedComponents = append(c.degradedComponents, ComponentStatus{
		Name:   name,
		Phase:  phase,
		Reason: reason,
	})
}

// stopComponents stops all enabled components after execution.
func (c *windowsEnhancedComponents) stopComponents(ctx context.Context) []error {
	var stopErrors []error

	// Stop kernel monitor
	if c.kernelMonitor != nil {
		if err := c.kernelMonitor.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("kernel monitor stop failed: %w", err))
		}
	}

	// Create final VSS snapshot
	if c.vssManager != nil && c.baselineSnapshot != nil {
		snapshot, err := c.vssManager.CreateSnapshot(ctx, "C:\\")
		if err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("final snapshot failed: %w", err))
		} else {
			c.finalSnapshot = snapshot
		}
	}

	// Stop WFP monitor
	if c.wfpMonitor != nil {
		if err := c.wfpMonitor.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("wfp monitor stop failed: %w", err))
		}
	}

	// Stop API tracer and wait for buffered API calls to finish draining
	if c.apiTracer != nil {
		if err := c.apiTracer.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("api tracer stop failed: %w", err))
		}
		c.mu.Lock()
		doneCh := c.apiCollectorDone
		c.mu.Unlock()
		if doneCh != nil {
			select {
			case <-doneCh:
			case <-time.After(100 * time.Millisecond):
			}
		}
		c.syncAPITracerDiagnostics()
	}

	// Disable time manipulation
	if c.timeManipulator != nil {
		if err := c.timeManipulator.Disable(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("time manipulator disable failed: %w", err))
		}
	}

	return stopErrors
}

// cleanup performs cleanup operations (delete snapshots, etc.).
func (c *windowsEnhancedComponents) cleanup() []error {
	var cleanupErrors []error

	// Delete VSS snapshots
	if c.vssManager != nil {
		if c.baselineSnapshot != nil {
			if err := c.vssManager.DeleteSnapshot(c.baselineSnapshot.ID); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("delete baseline snapshot failed: %w", err))
			}
		}
		if c.finalSnapshot != nil {
			if err := c.vssManager.DeleteSnapshot(c.finalSnapshot.ID); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("delete final snapshot failed: %w", err))
			}
		}
	}

	return cleanupErrors
}

// collectKernelEvents collects kernel events from the monitor.
func (c *windowsEnhancedComponents) collectKernelEvents(ctx context.Context) {
	if c.kernelMonitor == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-c.kernelMonitor.Events():
			if !ok {
				return
			}
			c.mu.Lock()
			// Enforce resource limit
			if !c.isSynthetic("kernel_monitor") && len(c.kernelEvents) < MaxKernelEvents {
				c.kernelEvents = append(c.kernelEvents, event)
			}
			c.mu.Unlock()
		}
	}
}

// collectAPICalls collects API calls from the tracer.
func (c *windowsEnhancedComponents) collectAPICalls(ctx context.Context, doneCh chan struct{}) {
	defer close(doneCh)
	if c.apiTracer == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case call, ok := <-c.apiTracer.Calls():
			if !ok {
				return
			}
			c.mu.Lock()
			// Enforce resource limit
			if !c.isSynthetic("api_tracing") && len(c.apiCalls) < MaxAPICalls {
				c.apiCalls = append(c.apiCalls, call)
			}
			c.mu.Unlock()
		}
	}
}

// drainReadyAPICalls non-blockingly drains any buffered calls still sitting in
// c.apiTracer.Calls() when analyzeAndPopulateReport is invoked directly.
func (c *windowsEnhancedComponents) drainReadyAPICallsLocked() {
	if c.apiTracer == nil || c.isSynthetic("api_tracing") {
		return
	}
	for len(c.apiCalls) < MaxAPICalls {
		select {
		case call, ok := <-c.apiTracer.Calls():
			if !ok {
				return
			}
			c.apiCalls = append(c.apiCalls, call)
		default:
			return
		}
	}
}

// analyzeAndPopulateReport performs post-execution analysis and populates the report.
func (c *windowsEnhancedComponents) analyzeAndPopulateReport(report *Report) error {
	c.syncAPITracerDiagnostics()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.drainReadyAPICallsLocked()

	// Check resource limits and add warnings
	report.StartedComponents = nil
	for _, name := range c.startedComponents {
		if !c.isSynthetic(name) {
			report.StartedComponents = append(report.StartedComponents, name)
		}
	}
	report.DegradedComponents = append([]ComponentStatus(nil), c.degradedComponents...)
	kernelEvents, apiCalls := c.observedTelemetry()

	if provider, ok := c.apiTracer.(apiTracerStatusProvider); ok {
		if dropped := provider.DroppedCalls(); dropped > 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf(
				"API tracer dropped %d calls due to bounded channel backpressure", dropped,
			))
		}
		if report.Frida == nil {
			if snap := provider.FridaSessionSnapshot(); snap != nil && (snap.Active || len(snap.Warnings) > 0) {
				report.Frida = snap
			}
		}
	}

	usage := ResourceUsage{
		KernelEventCount: len(kernelEvents),
		APICallCount:     len(apiCalls),
	}

	if c.wfpMonitor != nil && !c.isSynthetic("wfp") {
		usage.NetworkConnectionCount = len(c.wfpMonitor.Connections())
		usage.DNSQueryCount = len(c.wfpMonitor.DNSQueries())
		usage.TLSRecordCount = len(c.wfpMonitor.TLSMetadata())
	}

	report.ResourcePressure = AnalyzeResourcePressure(usage)
	limitWarnings := CheckResourceLimits(usage)
	report.Warnings = append(report.Warnings, limitWarnings...)

	// Populate kernel events
	report.KernelEvents = append([]KernelEvent(nil), kernelEvents...)

	// Populate API calls
	report.APICalls = append([]APICall(nil), apiCalls...)

	// Compare VSS snapshots
	if c.vssManager != nil && c.baselineSnapshot != nil && c.finalSnapshot != nil {
		diff, err := c.vssManager.CompareSnapshots(c.baselineSnapshot, c.finalSnapshot)
		if err != nil {
			return fmt.Errorf("snapshot comparison failed: %w", err)
		}
		report.VSSSnapshots = []Snapshot{*c.baselineSnapshot, *c.finalSnapshot}
		report.VSSComparison = diff
	}

	// Populate network capture
	report.NetworkCapture = nil
	if c.wfpMonitor != nil && !c.isSynthetic("wfp") {
		report.NetworkCapture = &NetworkCapture{
			Connections: c.wfpMonitor.Connections(),
			DNSQueries:  c.wfpMonitor.DNSQueries(),
			TLSMetadata: c.wfpMonitor.TLSMetadata(),
		}
	}

	// Populate time manipulation log
	if c.timeManipulator != nil {
		report.TimeManipulation = c.timeManipulator.GetLog()
	}

	// Run behavior analysis
	if c.behaviorClassifier != nil {
		events := c.convertToEvents()
		report.BehaviorAnalysis = c.behaviorClassifier.Analyze(events)
	}

	// Detect anti-sandbox techniques
	if c.antiSandboxDetector != nil {
		report.AntiSandboxDetected = c.antiSandboxDetector.Analyze(apiCalls, kernelEvents)
	}

	// Generate process graph
	if c.visualGenerator != nil && len(report.Processes) > 0 {
		var behaviors []BehaviorIndicator
		if report.BehaviorAnalysis != nil {
			behaviors = report.BehaviorAnalysis.Indicators
		}

		graph, err := c.visualGenerator.GenerateProcessGraph(report.Processes, behaviors)
		if err != nil {
			return fmt.Errorf("process graph generation failed: %w", err)
		}
		report.ProcessGraph = graph

		// Generate timeline
		timeline, err := c.visualGenerator.GenerateTimeline(c.convertToEvents(), behaviors)
		if err != nil {
			return fmt.Errorf("timeline generation failed: %w", err)
		}
		report.Timeline = timeline
	}

	return nil
}

// isSynthetic and observedTelemetry require c.mu when collectors are active.
func (c *windowsEnhancedComponents) isSynthetic(name string) bool {
	for _, status := range c.degradedComponents {
		if status.Name == name && status.Phase == "synthetic" {
			return true
		}
	}
	return false
}

func (c *windowsEnhancedComponents) observedTelemetry() ([]KernelEvent, []APICall) {
	kernelEvents, apiCalls := c.kernelEvents, c.apiCalls
	if c.isSynthetic("kernel_monitor") {
		kernelEvents = nil
	}
	if c.isSynthetic("api_tracing") {
		apiCalls = nil
	}
	return kernelEvents, apiCalls
}

// convertToEvents supplies observed, chronological events to all consumers.
func (c *windowsEnhancedComponents) convertToEvents() []Event {
	kernelEvents, apiCalls := c.observedTelemetry()
	events := make([]Event, 0, len(kernelEvents)+len(apiCalls))

	for _, ke := range kernelEvents {
		events = append(events, ke)
	}

	for _, ac := range apiCalls {
		events = append(events, ac)
	}

	sort.SliceStable(events, func(i, j int) bool {
		return events[i].GetTimestamp().Before(events[j].GetTimestamp())
	})

	return events
}

// exportArtifacts exports additional artifacts (PCAP, DOT, HTML).
func (c *windowsEnhancedComponents) exportArtifacts(sessionDir string, report *Report) []error {
	var exportErrors []error

	// Export PCAP
	if c.wfpMonitor != nil && report.NetworkCapture != nil {
		pcapPath := sessionDir + "/network_capture.pcap"
		if err := c.wfpMonitor.ExportPCAP(pcapPath); err != nil {
			exportErrors = append(exportErrors, fmt.Errorf("pcap export failed: %w", err))
		} else if report.NetworkCapture != nil {
			report.NetworkCapture.PCAPPath = pcapPath
		}
	}

	// Export process graph DOT
	if c.visualGenerator != nil && report.ProcessGraph != "" {
		dotPath := sessionDir + "/process_graph.dot"
		if err := c.visualGenerator.ExportDOT(dotPath, report.ProcessGraph); err != nil {
			exportErrors = append(exportErrors, fmt.Errorf("dot export failed: %w", err))
		}
	}

	// Export timeline HTML
	if c.visualGenerator != nil && report.Timeline != "" {
		htmlPath := sessionDir + "/timeline.html"
		if err := c.visualGenerator.ExportHTML(htmlPath, report.Timeline); err != nil {
			exportErrors = append(exportErrors, fmt.Errorf("html export failed: %w", err))
		}
	}

	return exportErrors
}
