//go:build !windows

package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNonWindowsOSStubsReturnSafeDefaults(t *testing.T) {
	prepareCommand(exec.Command("echo", "ok"))

	if err := resumeProcess(123); err == nil || !strings.Contains(err.Error(), "Windows only") {
		t.Fatalf("resumeProcess error = %v", err)
	}
	if err := applyCPUAffinity(123, 1); err != nil {
		t.Fatalf("applyCPUAffinity = %v", err)
	}
	if guard, err := newProcessGuard(512); err == nil || guard != nil {
		t.Fatalf("newProcessGuard = (%v, %v), want nil Windows-only error", guard, err)
	}
	if guard, err := newBlockingNetworkGuard("sample.exe", "session"); err == nil || guard != nil {
		t.Fatalf("newBlockingNetworkGuard = (%v, %v), want nil Windows-only error", guard, err)
	}
	if processes, connections, err := collectSnapshot(1); err == nil || processes != nil || connections != nil {
		t.Fatalf("collectSnapshot = (%v, %v, %v), want nils and error", processes, connections, err)
	}
	if registry, err := captureAutorunSnapshot(); err == nil || registry != nil {
		t.Fatalf("captureAutorunSnapshot = (%v, %v), want nil and error", registry, err)
	}
	input := []ObservedProcess{{PID: 7, Name: "sample"}}
	if got := enrichObservedProcesses(input); len(got) != 1 || got[0].PID != input[0].PID {
		t.Fatalf("enrichObservedProcesses = %+v", got)
	}
	if err := checkPrivileges(); err == nil || !strings.Contains(err.Error(), "Windows only") {
		t.Fatalf("checkPrivileges error = %v", err)
	}
	if isAdmin() {
		t.Fatal("isAdmin should be false on non-Windows")
	}
}

func TestNonWindowsEnhancedComponentStubsAreNoops(t *testing.T) {
	if components, err := initializeEnhancedComponents(Config{}); err == nil || components != nil {
		t.Fatalf("initializeEnhancedComponents = (%v, %v), want nil and error", components, err)
	}

	components := &windowsEnhancedComponents{}
	if err := components.startComponents(context.Background(), Config{}, 123); err != nil {
		t.Fatalf("startComponents = %v", err)
	}
	if errs := components.stopComponents(context.Background()); errs != nil {
		t.Fatalf("stopComponents = %v", errs)
	}
	if errs := components.cleanup(); errs != nil {
		t.Fatalf("cleanup = %v", errs)
	}
	if err := components.analyzeAndPopulateReport(&Report{}); err != nil {
		t.Fatalf("analyzeAndPopulateReport = %v", err)
	}
	if errs := components.exportArtifacts(t.TempDir(), &Report{}); errs != nil {
		t.Fatalf("exportArtifacts = %v", errs)
	}
}

func TestNonWindowsAPITracerStubLifecycle(t *testing.T) {
	tracer := newAPITracer([]string{"file"})
	if err := tracer.Attach(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "Windows") {
		t.Fatalf("Attach error = %v", err)
	}
	if err := tracer.Detach(1); err == nil || !strings.Contains(err.Error(), "Windows") {
		t.Fatalf("Detach error = %v", err)
	}
	calls := tracer.Calls()
	if err := tracer.Stop(); err != nil {
		t.Fatalf("Stop = %v", err)
	}
	if _, ok := <-calls; ok {
		t.Fatal("calls channel should be closed after Stop")
	}
}

func TestKernelMonitorNonWindowsPathsAndEventGetters(t *testing.T) {
	monitor := NewKernelMonitor()
	impl, ok := monitor.(*kernelMonitorImpl)
	if !ok {
		t.Fatalf("NewKernelMonitor returned %T", monitor)
	}
	impl.SetProcessFilter([]int{10, 20})
	if !impl.filterEnabled || len(impl.targetPIDs) != 2 {
		t.Fatalf("process filter not enabled correctly: %+v", impl.targetPIDs)
	}
	impl.SetProcessFilter(nil)
	if impl.filterEnabled || len(impl.targetPIDs) != 0 {
		t.Fatalf("process filter not disabled correctly: %+v", impl.targetPIDs)
	}
	if err := impl.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Fatalf("Start error = %v", err)
	}
	if err := impl.Stop(); err != nil {
		t.Fatalf("Stop = %v", err)
	}
	if impl.Events() == nil {
		t.Fatal("Events channel is nil")
	}
	if _, err := impl.connectToPipe(context.Background()); err == nil {
		t.Fatal("connectToPipe should fail on non-Windows")
	}
	if _, err := impl.readEvent(pipeHandle{}, nil); err == nil {
		t.Fatal("readEvent should fail on non-Windows")
	}
	impl.closePipe(pipeHandle{})
	if err := impl.verifyDriverLoaded(); err == nil {
		t.Fatal("verifyDriverLoaded should fail on non-Windows")
	}

	now := time.Now().UTC()
	kernelEvent := KernelEvent{Timestamp: now, ProcessID: 42, EventType: EventFileWrite}
	if !kernelEvent.GetTimestamp().Equal(now) || kernelEvent.GetProcessID() != 42 || kernelEvent.GetEventType() != "FileWrite" {
		t.Fatalf("kernel event getters returned unexpected values")
	}
	apiCall := APICall{Timestamp: now, ProcessID: 43, Function: "CreateFileW"}
	if !apiCall.GetTimestamp().Equal(now) || apiCall.GetProcessID() != 43 || apiCall.GetEventType() != "APICall:CreateFileW" {
		t.Fatalf("api call getters returned unexpected values")
	}
	conn := NetworkConnection{Timestamp: now, ProcessID: 44, Protocol: "tcp"}
	if !conn.GetTimestamp().Equal(now) || conn.GetProcessID() != 44 || conn.GetEventType() != "NetworkConnection:tcp" {
		t.Fatalf("network connection getters returned unexpected values")
	}
}

func TestNonWindowsOptionalComponentStubs(t *testing.T) {
	tm := newTimeManipulator()
	if err := tm.Enable(2); err == nil || !strings.Contains(err.Error(), "Windows") {
		t.Fatalf("time Enable error = %v", err)
	}
	if err := tm.Disable(); err != nil {
		t.Fatalf("time Disable = %v", err)
	}
	if tm.GetVirtualTime().IsZero() || tm.GetRealTime().IsZero() {
		t.Fatal("time getters should return non-zero times")
	}
	if tm.GetOffset() != 0 {
		t.Fatalf("time offset = %v, want 0", tm.GetOffset())
	}
	if log := tm.GetLog(); log == nil || log.Enabled || log.ScaleFactor != 1.0 || len(log.SkipEvents) != 0 {
		t.Fatalf("time log = %+v", log)
	}

	vss := newVSSManager()
	if snapshot, err := vss.CreateSnapshot(context.Background(), "C:\\"); err == nil || snapshot != nil {
		t.Fatalf("CreateSnapshot = (%v, %v), want nil and error", snapshot, err)
	}
	if err := vss.DeleteSnapshot("snap"); err == nil {
		t.Fatal("DeleteSnapshot should fail on non-Windows")
	}
	if diff, err := vss.CompareSnapshots(&Snapshot{}, &Snapshot{}); err == nil || diff != nil {
		t.Fatalf("CompareSnapshots = (%v, %v), want nil and error", diff, err)
	}

	wfp := NewWFPMonitor()
	if err := wfp.Start(context.Background(), []int{1}); err == nil || !strings.Contains(err.Error(), "Windows") {
		t.Fatalf("WFP Start error = %v", err)
	}
	if err := wfp.Stop(); err != nil {
		t.Fatalf("WFP Stop = %v", err)
	}
	if len(wfp.Connections()) != 0 || len(wfp.DNSQueries()) != 0 || len(wfp.TLSMetadata()) != 0 {
		t.Fatal("WFP stub collections should be empty")
	}
	if err := wfp.ExportPCAP("out.pcap"); err == nil || !strings.Contains(err.Error(), "PCAP") {
		t.Fatalf("ExportPCAP error = %v", err)
	}

	vg := newVisualGenerator()
	if graph, err := vg.GenerateProcessGraph(nil, nil); err == nil || graph != "" {
		t.Fatalf("GenerateProcessGraph = (%q, %v), want empty and error", graph, err)
	}
	if timeline, err := vg.GenerateTimeline(nil, nil); err == nil || timeline != "" {
		t.Fatalf("GenerateTimeline = (%q, %v), want empty and error", timeline, err)
	}
	if err := vg.ExportDOT("out.dot", "graph"); err == nil {
		t.Fatal("ExportDOT should fail on non-Windows")
	}
	if err := vg.ExportHTML("out.html", "timeline"); err == nil {
		t.Fatal("ExportHTML should fail on non-Windows")
	}
}
