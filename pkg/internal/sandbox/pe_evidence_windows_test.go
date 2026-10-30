//go:build windows

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func injectionTrace(pid int, start time.Time) []Event {
	return []Event{
		APICall{Timestamp: start, ProcessID: pid, Function: "VirtualAllocEx"},
		APICall{Timestamp: start.Add(time.Second), ProcessID: pid, Function: "WriteProcessMemory"},
		APICall{Timestamp: start.Add(2 * time.Second), ProcessID: pid, Function: "CreateRemoteThread"},
	}
}

func hasTechnique(analysis *BehaviorAnalysis, id string) bool {
	return slices.ContainsFunc(analysis.Techniques, func(tech MITRETechnique) bool { return tech.ID == id })
}

func TestPEBehaviorCorrelation(t *testing.T) {
	start := time.Unix(1000, 0)
	for _, tc := range []struct {
		name string
		edit func([]Event) []Event
		want bool
	}{
		{"complete sequence", func(e []Event) []Event { return e }, true},
		{"collector arrival order", func(e []Event) []Event { return []Event{e[2], e[0], e[1]} }, true},
		{"different processes", func(e []Event) []Event {
			call := e[1].(APICall)
			call.ProcessID = 200
			e[1] = call
			return e
		}, false},
		{"outside time window", func(e []Event) []Event {
			call := e[2].(APICall)
			call.Timestamp = start.Add(30 * time.Second)
			e[2] = call
			return e
		}, false},
		{"wrong chronological order", func(e []Event) []Event {
			call := e[1].(APICall)
			call.Timestamp = start.Add(-time.Second)
			e[1] = call
			return e
		}, false},
		{"partial sequence", func(e []Event) []Event { return e[:2] }, false},
		{"different API name", func(e []Event) []Event {
			call := e[0].(APICall)
			call.Function = "VirtualAllocExNuma"
			e[0] = call
			return e
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := tc.edit(injectionTrace(100, start))
			before := append([]Event(nil), events...)
			analysis := NewBehaviorClassifier().Analyze(events)
			if got := hasTechnique(analysis, "T1055"); got != tc.want {
				t.Fatalf("injection=%v, want %v; %+v", got, tc.want, analysis)
			}
			for i := range events {
				if events[i].GetTimestamp() != before[i].GetTimestamp() {
					t.Fatal("classifier reordered caller-owned events")
				}
			}
		})
	}
}

func TestPEBehaviorRequiresWholeCustomSequence(t *testing.T) {
	classifier := &windowsBehaviorClassifier{}
	rule := ProcessInjectionRule()
	rule.Pattern.MinMatches = 1
	if err := classifier.AddRule(rule); err != nil {
		t.Fatal(err)
	}
	if got := classifier.Analyze(injectionTrace(1, time.Now())[:1]); len(got.Techniques) != 0 {
		t.Fatalf("minimum matches bypassed mandatory steps: %+v", got)
	}
}

func TestPEBehaviorRepeatedEventsStayWithinProcessAndWindow(t *testing.T) {
	var events []Event
	start := time.Unix(1000, 0)
	for i := 0; i < 12; i++ {
		events = append(events, APICall{Timestamp: start.Add(time.Duration(i) * time.Second), ProcessID: 1 + i%2, Function: "CryptEncrypt"})
	}
	classifier := NewBehaviorClassifier()
	if got := classifier.Analyze(events); hasTechnique(got, "T1486") {
		t.Fatal("encryption operations from unrelated PIDs were combined")
	}
	for i := range events {
		call := events[i].(APICall)
		call.ProcessID = 1
		call.Timestamp = start.Add(time.Duration(i) * time.Minute)
		events[i] = call
	}
	slices.Reverse(events)
	if got := classifier.Analyze(events); hasTechnique(got, "T1486") {
		t.Fatal("unsorted events bypassed the time window")
	}
}

func TestPEBehaviorFindsLaterCompleteSequence(t *testing.T) {
	start := time.Unix(1000, 0)
	events := append(injectionTrace(1, start)[:1], injectionTrace(1, start.Add(time.Minute))...)
	if got := NewBehaviorClassifier().Analyze(events); !hasTechnique(got, "T1055") {
		t.Fatalf("expired partial sequence hid the later valid sequence: %+v", got)
	}
}

func TestPEBehaviorCustomFilterValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		filter map[string]interface{}
		want   bool
	}{
		{"JSON string array", map[string]interface{}{"path_contains": []interface{}{`\CURRENTVERSION\RUN`}}, true},
		{"wrong value type", map[string]interface{}{"path_contains": 42}, false},
		{"wrong array member", map[string]interface{}{"path_contains": []interface{}{42}}, false},
		{"unknown filter", map[string]interface{}{"misspelled_filter": "Run"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := RegistryPersistenceRule()
			rule.Pattern.Sequence[0].Filters = tc.filter
			classifier := &windowsBehaviorClassifier{rules: []ClassificationRule{rule}}
			analysis := classifier.Analyze([]Event{KernelEvent{
				Timestamp: time.Now(), ProcessID: 1, EventType: EventRegSetValue,
				Path: `HKCU\software\microsoft\windows\currentversion\run\App`,
			}})
			if got := hasTechnique(analysis, "T1547"); got != tc.want {
				t.Fatalf("persistence=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestPEAPITracerDoesNotInventEvidence(t *testing.T) {
	tracer := NewAPITracer(nil)
	if err := tracer.Attach(context.Background(), 1234); !errors.Is(err, errAPITracingUnavailable) {
		t.Fatalf("missing backend must be explicit: %v", err)
	}
	if err := tracer.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := tracer.Stop(); err != nil {
		t.Fatal(err)
	}
	if call, ok := <-tracer.Calls(); ok {
		t.Fatalf("unavailable tracer emitted a call: %+v", call)
	}
}

func TestPESyntheticTelemetryExcludedFromReport(t *testing.T) {
	start := time.Unix(1000, 0)
	components := &windowsEnhancedComponents{
		behaviorClassifier: NewBehaviorClassifier(), antiSandboxDetector: NewAntiSandboxDetector(),
		wfpMonitor: NewWFPMonitor(),
		kernelEvents: []KernelEvent{{Timestamp: start, ProcessID: 1, EventType: EventRegSetValue,
			Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\App`}},
		startedComponents: []string{"api_tracing", "kernel_monitor", "wfp"},
	}
	for _, event := range injectionTrace(1, start) {
		components.apiCalls = append(components.apiCalls, event.(APICall))
	}
	for _, name := range components.startedComponents {
		components.addSynthetic(name, "test fixture")
	}
	report := &Report{}
	if err := components.analyzeAndPopulateReport(report); err != nil {
		t.Fatal(err)
	}
	if len(report.KernelEvents)+len(report.APICalls)+len(report.StartedComponents) != 0 || report.NetworkCapture != nil {
		t.Fatalf("synthetic observations leaked into report: %+v", report)
	}
	if report.BehaviorAnalysis.RiskScore != 0 || len(report.AntiSandboxDetected) != 0 || len(components.convertToEvents()) != 0 {
		t.Fatal("synthetic data became behavioral evidence")
	}
	if len(report.DegradedComponents) != 3 || report.BehaviorAnalysis.Classification != "Unknown" {
		t.Fatal("missing coverage must stay visible without declaring the sample benign")
	}
	// Real observations must still reach the analyzer after the provenance gate.
	components.degradedComponents = nil
	components.wfpMonitor = nil
	if err := components.analyzeAndPopulateReport(report); err != nil {
		t.Fatal(err)
	}
	if !hasTechnique(report.BehaviorAnalysis, "T1055") || !hasTechnique(report.BehaviorAnalysis, "T1547") {
		t.Fatal("observed evidence was lost")
	}
}

func TestPEComponentsKeepUnprivilegedAnalysis(t *testing.T) {
	previous := checkPrivilegesFunc
	checkPrivilegesFunc = func() error { return errors.New("not elevated") }
	t.Cleanup(func() { checkPrivilegesFunc = previous })
	components, err := initializeEnhancedComponents(Config{})
	if err != nil || components == nil || components.behaviorClassifier == nil || components.visualGenerator == nil {
		t.Fatalf("basic analysis unnecessarily requires elevation: %v", err)
	}
	components, err = initializeEnhancedComponents(Config{EnableKernelMonitor: true, EnableVSS: true, EnableAPITracing: true})
	if err == nil || components == nil || components.behaviorClassifier == nil {
		t.Fatal("privileged collector failure discarded offline analysis")
	}
	if components.kernelMonitor != nil || components.vssManager != nil || len(components.degradedComponents) != 2 {
		t.Fatal("unavailable privileged collectors not identified")
	}
	if err := components.startComponents(context.Background(), Config{}, 1234); !errors.Is(err, errAPITracingUnavailable) {
		t.Fatalf("API backend failure was not reported: %v", err)
	}
	t.Cleanup(func() { components.stopComponents(context.Background()) })
	report := &Report{}
	if err := components.analyzeAndPopulateReport(report); err != nil || len(report.DegradedComponents) != 3 {
		t.Fatalf("missing component status: %+v, %v", report.DegradedComponents, err)
	}
}

type peObservedKernelMonitor struct{ events chan KernelEvent }

func (m *peObservedKernelMonitor) Start(context.Context) error { return nil }
func (m *peObservedKernelMonitor) Stop() error                 { return nil }
func (m *peObservedKernelMonitor) Events() <-chan KernelEvent  { return m.events }
func (m *peObservedKernelMonitor) SetProcessFilter([]int)      {}

func apiWithTarget(fn string, pid int, ts time.Time, ret string, params ...APIParameter) APICall {
	return APICall{Timestamp: ts, ProcessID: pid, Function: fn, Parameters: params, ReturnValue: ret}
}

func TestPEChainArgumentConfirmation(t *testing.T) {
	start := time.Unix(2000, 0)
	h1 := []APIParameter{{Name: "hProcess", Type: "HANDLE", Value: "0x1234"}}
	h2 := []APIParameter{{Name: "hProcess", Type: "HANDLE", Value: "0x5678"}}
	bc := NewBehaviorClassifier()
	// A/W + NT aliases form the same chain when target and success agree.
	aliased := []Event{
		apiWithTarget("VirtualAllocEx", 100, start, "0x20000", h1...),
		apiWithTarget("NtWriteVirtualMemory", 100, start.Add(time.Second), "0", h1...),
		apiWithTarget("CreateRemoteThreadW", 100, start.Add(2*time.Second), "0x300", h1...),
	}
	if got := bc.Analyze(aliased); !hasTechnique(got, "T1055") {
		t.Error("A/W + NT aliases with same target should confirm T1055")
	}
	// Different explicit targets must not confirm.
	split := []Event{
		apiWithTarget("VirtualAllocEx", 100, start, "0x20000", h1...),
		apiWithTarget("WriteProcessMemory", 100, start.Add(time.Second), "0x200", h2...),
		apiWithTarget("CreateRemoteThread", 100, start.Add(2*time.Second), "0x300", h1...),
	}
	if got := bc.Analyze(split); hasTechnique(got, "T1055") {
		t.Error("different hProcess targets must not confirm T1055")
	}
	// Failed middle call (NULL return) must not confirm.
	failed := []Event{
		apiWithTarget("VirtualAllocEx", 100, start, "0x20000", h1...),
		apiWithTarget("WriteProcessMemory", 100, start.Add(time.Second), "0x0", h1...),
		apiWithTarget("CreateRemoteThread", 100, start.Add(2*time.Second), "0x300", h1...),
	}
	if got := bc.Analyze(failed); hasTechnique(got, "T1055") {
		t.Error("failed WriteProcessMemory (0x0) must not confirm T1055")
	}
	// Failed NTSTATUS must not confirm either (0 == success for NT).
	ntFail := []Event{
		apiWithTarget("NtAllocateVirtualMemory", 100, start, "0", h1...),
		apiWithTarget("NtWriteVirtualMemory", 100, start.Add(time.Second), "0", h1...),
		apiWithTarget("NtCreateThreadEx", 100, start.Add(2*time.Second), "0xC0000022", h1...),
	}
	if got := bc.Analyze(ntFail); hasTechnique(got, "T1055") {
		t.Error("failed NTSTATUS chain must not confirm T1055")
	}
}

func TestPEKernelSourceNotAutomaticallySynthetic(t *testing.T) {
	// Replace the OS transport, not the report/classification path. A working
	// external source must survive startComponents and the provenance filter.
	events := make(chan KernelEvent)
	close(events)
	components := &windowsEnhancedComponents{
		kernelMonitor:      &peObservedKernelMonitor{events: events},
		behaviorClassifier: NewBehaviorClassifier(),
	}
	if err := components.startComponents(context.Background(), Config{}, 1); err != nil {
		t.Fatal(err)
	}
	components.mu.Lock()
	components.kernelEvents = append(components.kernelEvents, KernelEvent{
		Timestamp: time.Now(), ProcessID: 1, EventType: EventRegSetValue,
		Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\App`,
	})
	components.mu.Unlock()
	report := &Report{}
	if err := components.analyzeAndPopulateReport(report); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(report.StartedComponents, "kernel_monitor") || len(report.KernelEvents) != 1 || !hasTechnique(report.BehaviorAnalysis, "T1547") {
		t.Fatalf("observed kernel data was suppressed: %+v", report)
	}
}

func TestPEChainExtendedAliasesTargetsAndReturnCodes(t *testing.T) {
	start := time.Unix(3000, 0)
	bc := NewBehaviorClassifier()

	// (a) Zw/Nt + A/W aliases for Process Hollowing (T1055.012) with matching hProcess and hThread.
	hollowingOK := []Event{
		apiWithTarget("CreateProcessW", 300, start, "0x1",
			APIParameter{Name: "dwCreationFlags", Type: "DWORD", Value: "CREATE_SUSPENDED"},
			APIParameter{Name: "hProcess", Type: "HANDLE", Value: "0x400"},
			APIParameter{Name: "hThread", Type: "HANDLE", Value: "0x404"},
		),
		apiWithTarget("ZwUnmapViewOfSection", 300, start.Add(time.Second), "0x00000000",
			APIParameter{Name: "ProcessHandle", Type: "HANDLE", Value: "0x400"},
		),
		apiWithTarget("NtWriteVirtualMemory", 300, start.Add(2*time.Second), "0x00000000",
			APIParameter{Name: "ProcessHandle", Type: "HANDLE", Value: "0x400"},
		),
		apiWithTarget("NtResumeThread", 300, start.Add(3*time.Second), "0x00000000",
			APIParameter{Name: "ThreadHandle", Type: "HANDLE", Value: "0x404"},
		),
	}
	if got := bc.Analyze(hollowingOK); !hasTechnique(got, "T1055.012") {
		t.Fatalf("expected T1055.012 for aliased hollowing chain, got %+v", got)
	}

	// (b) Mixed Win32 hProcess and Native ProcessHandle with different handles must break T1055.
	mixedHandleMismatch := []Event{
		apiWithTarget("VirtualAllocEx", 300, start, "0x100000",
			APIParameter{Name: "hProcess", Type: "HANDLE", Value: "0x400"},
		),
		apiWithTarget("NtWriteVirtualMemory", 300, start.Add(time.Second), "0x00000000",
			APIParameter{Name: "ProcessHandle", Type: "HANDLE", Value: "0x999"},
		),
		apiWithTarget("RtlCreateUserThread", 300, start.Add(2*time.Second), "0x00000000",
			APIParameter{Name: "ProcessHandle", Type: "HANDLE", Value: "0x400"},
		),
	}
	if got := bc.Analyze(mixedHandleMismatch); hasTechnique(got, "T1055") {
		t.Fatal("mixed Win32 hProcess and NT ProcessHandle targeting different handles must break T1055")
	}

	// (c) Failed ResumeThread (0xffffffff) or non-zero NTSTATUS (0x80000005) breaks hollowing/injection.
	hollowingFailedResume := append([]Event(nil), hollowingOK...)
	hollowingFailedResume[3] = apiWithTarget("ResumeThread", 300, start.Add(3*time.Second), "0xffffffff",
		APIParameter{Name: "hThread", Type: "HANDLE", Value: "0x404"},
	)
	if got := bc.Analyze(hollowingFailedResume); hasTechnique(got, "T1055.012") {
		t.Fatal("failed ResumeThread (0xffffffff) must break T1055.012")
	}

	// Failed CryptEncrypt calls (0x0) must not count toward T1486 ransomware threshold.
	var failedCrypto []Event
	for i := 0; i < 12; i++ {
		failedCrypto = append(failedCrypto, APICall{
			Timestamp:   start.Add(time.Duration(i) * time.Second),
			ProcessID:   300,
			Function:    "CryptEncrypt",
			ReturnValue: "0x0",
			LastError:   87,
		})
	}
	if got := bc.Analyze(failedCrypto); hasTechnique(got, "T1486") {
		t.Fatal("failed CryptEncrypt calls (0x0) must not trigger T1486")
	}
}

type fakeFridaStream struct {
	pr        *io.PipeReader
	pw        *io.PipeWriter
	closeOnce sync.Once
}

func newFakeFridaStream(lines ...string) *fakeFridaStream {
	pr, pw := io.Pipe()
	s := &fakeFridaStream{pr: pr, pw: pw}
	go func() {
		for _, line := range lines {
			_, _ = io.WriteString(pw, line+"\n")
		}
	}()
	return s
}

func (s *fakeFridaStream) Stdout() io.Reader { return s.pr }

func (s *fakeFridaStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.pw.Close()
		_ = s.pr.Close()
	})
	return nil
}

type fakeFridaDriver struct {
	mu          sync.Mutex
	probeFn     func(pid int) (targetProcessInfo, error)
	resolveFn   func(targetArch string, pid int) (fridaToolchainInfo, error)
	sessionByID map[int]*fakeFridaStream
	attachedIDs []int
}

func (d *fakeFridaDriver) ProbeProcess(pid int) (targetProcessInfo, error) {
	if d.probeFn != nil {
		return d.probeFn(pid)
	}
	return targetProcessInfo{PID: pid, Arch: "x86_64", PointerSize: 8}, nil
}

func (d *fakeFridaDriver) ResolveToolchain(targetArch string, pid int) (fridaToolchainInfo, error) {
	if d.resolveFn != nil {
		return d.resolveFn(targetArch, pid)
	}
	return fridaToolchainInfo{
		FridaBin:      "frida",
		HostVersion:   "16.4.2",
		ServerBinary:  "frida-server-16.4.2-windows-x86_64.exe",
		ServerVersion: "16.4.2",
		TargetArch:    targetArch,
	}, nil
}

func (d *fakeFridaDriver) StartSession(_ context.Context, pid int, _ targetProcessInfo, _ fridaToolchainInfo, _ []string) (fridaSessionStream, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.attachedIDs = append(d.attachedIDs, pid)
	if s, ok := d.sessionByID[pid]; ok {
		return s, "", nil
	}
	return nil, "", fmt.Errorf("%w: no session configured for PID %d", errTargetProcessExited, pid)
}

func TestPERealCollectorReachesBehaviorAnalysisAndFollowsChildren(t *testing.T) {
	// (d) Prove that events from the real windowsAPITracer collector (including
	// child process follow via FRIDA_CHILD) reach BehaviorAnalysis and are NOT
	// filtered as synthetic.
	rootPID := 4100
	childPID := 4200
	baseMS := time.Unix(4000, 0).UnixMilli()

	rootStream := newFakeFridaStream(
		`FRIDA_SESSION {"type":"ready","pid":4100,"arch":"x64","pointer_size":8,"hooked":["kernel32.dll!CreateProcessW"],"gaps":[]}`,
		fmt.Sprintf(`FRIDA_API {"ts":%d,"pid":4100,"tid":4104,"cat":"Process","mod":"kernel32.dll","fn":"CreateProcessW","params":[{"name":"lpApplicationName","type":"LPCWSTR","value":"C:\\Windows\\System32\\svchost.exe"},{"name":"dwCreationFlags","type":"DWORD","value":"CREATE_SUSPENDED"},{"name":"hProcess","type":"HANDLE","value":"0x500"},{"name":"hThread","type":"HANDLE","value":"0x504"},{"name":"dwProcessId","type":"DWORD","value":"4200"}],"ret":"0x1","err":0}`, baseMS),
		`FRIDA_CHILD {"parent_pid":4100,"child_pid":4200,"child_tid":4204,"suspended":true,"fn":"CreateProcessW"}`,
		fmt.Sprintf(`FRIDA_API {"ts":%d,"pid":4100,"tid":4104,"cat":"Process","mod":"ntdll.dll","fn":"NtUnmapViewOfSection","params":[{"name":"ProcessHandle","type":"HANDLE","value":"0x500"},{"name":"BaseAddress","type":"PVOID","value":"0x140000000"}],"ret":"0x00000000","err":0}`, baseMS+500),
		fmt.Sprintf(`FRIDA_API {"ts":%d,"pid":4100,"tid":4104,"cat":"Memory","mod":"kernel32.dll","fn":"WriteProcessMemory","params":[{"name":"hProcess","type":"HANDLE","value":"0x500"},{"name":"lpBaseAddress","type":"LPVOID","value":"0x140000000"},{"name":"nSize","type":"SIZE_T","value":"0x1000"}],"ret":"0x1","err":0}`, baseMS+1000),
		fmt.Sprintf(`FRIDA_API {"ts":%d,"pid":4100,"tid":4104,"cat":"Process","mod":"kernel32.dll","fn":"ResumeThread","params":[{"name":"hThread","type":"HANDLE","value":"0x504"}],"ret":"0x1","err":0}`, baseMS+1500),
	)

	childStream := newFakeFridaStream(
		`FRIDA_SESSION {"type":"ready","pid":4200,"arch":"x64","pointer_size":8,"hooked":["kernel32.dll!VirtualAllocEx","ntdll.dll!NtWriteVirtualMemory","kernel32.dll!CreateRemoteThread"],"gaps":[]}`,
		fmt.Sprintf(`FRIDA_API {"ts":%d,"pid":4200,"tid":4204,"cat":"Memory","mod":"kernel32.dll","fn":"VirtualAllocEx","params":[{"name":"hProcess","type":"HANDLE","value":"0x700"},{"name":"dwSize","type":"SIZE_T","value":"0x2000"}],"ret":"0x300000","err":0}`, baseMS+2000),
		fmt.Sprintf(`FRIDA_API {"ts":%d,"pid":4200,"tid":4204,"cat":"Memory","mod":"ntdll.dll","fn":"NtWriteVirtualMemory","params":[{"name":"ProcessHandle","type":"HANDLE","value":"0x700"},{"name":"BaseAddress","type":"PVOID","value":"0x300000"}],"ret":"0x00000000","err":0}`, baseMS+2500),
		fmt.Sprintf(`FRIDA_API {"ts":%d,"pid":4200,"tid":4204,"cat":"Process","mod":"kernel32.dll","fn":"CreateRemoteThread","params":[{"name":"hProcess","type":"HANDLE","value":"0x700"},{"name":"lpStartAddress","type":"LPTHREAD_START_ROUTINE","value":"0x300000"}],"ret":"0x704","err":0}`, baseMS+3000),
	)

	driver := &fakeFridaDriver{
		sessionByID: map[int]*fakeFridaStream{
			rootPID:  rootStream,
			childPID: childStream,
		},
	}

	tracer := newWindowsAPITracerWithConfig(nil, 128, driver)
	components := &windowsEnhancedComponents{
		apiTracer:           tracer,
		behaviorClassifier:  NewBehaviorClassifier(),
		antiSandboxDetector: NewAntiSandboxDetector(),
	}

	ctx := context.Background()
	if err := components.startComponents(ctx, Config{EnableAPITracing: true}, rootPID); err != nil {
		t.Fatalf("startComponents failed: %v", err)
	}

	// Wait briefly for root and child streams to emit all 7 events, then close streams.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		components.mu.Lock()
		count := len(components.apiCalls)
		components.mu.Unlock()
		if count >= 7 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = rootStream.Close()
	_ = childStream.Close()

	if errs := components.stopComponents(ctx); len(errs) != 0 {
		t.Fatalf("stopComponents returned errors: %v", errs)
	}

	report := &Report{}
	if err := components.analyzeAndPopulateReport(report); err != nil {
		t.Fatalf("analyzeAndPopulateReport failed: %v", err)
	}

	if !slices.Contains(report.StartedComponents, "api_tracing") {
		t.Fatalf("expected api_tracing in StartedComponents, got %v", report.StartedComponents)
	}
	if len(report.APICalls) != 7 {
		t.Fatalf("expected 7 real APICalls (4 root + 3 child), got %d: %+v", len(report.APICalls), report.APICalls)
	}
	if !hasTechnique(report.BehaviorAnalysis, "T1055.012") {
		t.Fatalf("expected root hollowing chain T1055.012 in BehaviorAnalysis, got %+v", report.BehaviorAnalysis)
	}
	if !hasTechnique(report.BehaviorAnalysis, "T1055") {
		t.Fatalf("expected child injection chain T1055 in BehaviorAnalysis, got %+v", report.BehaviorAnalysis)
	}
	if report.Frida == nil || !report.Frida.Active || report.Frida.EventCount != 7 {
		t.Fatalf("expected populated FridaSession with 7 events, got %+v", report.Frida)
	}
}

func TestPEAPITracerFailureModesAndBackpressure(t *testing.T) {
	t.Run("version mismatch", func(t *testing.T) {
		driver := &fakeFridaDriver{
			resolveFn: func(targetArch string, pid int) (fridaToolchainInfo, error) {
				return fridaToolchainInfo{}, fmt.Errorf("%w: host 16.4.2 vs server 15.1.0", errFridaVersionMismatch)
			},
		}
		tracer := newWindowsAPITracerWithConfig(nil, 16, driver)
		defer tracer.Stop()
		err := tracer.Attach(context.Background(), 5000)
		if !errors.Is(err, errAPITracingUnavailable) || !errors.Is(err, errFridaVersionMismatch) {
			t.Fatalf("expected errFridaVersionMismatch wrapping errAPITracingUnavailable, got %v", err)
		}
	})

	t.Run("32/64-bit ABI mismatch during handshake", func(t *testing.T) {
		stream := newFakeFridaStream(
			`FRIDA_SESSION {"type":"ready","pid":5001,"arch":"ia32","pointer_size":4,"hooked":[],"gaps":[]}`,
		)
		driver := &fakeFridaDriver{
			probeFn: func(pid int) (targetProcessInfo, error) {
				return targetProcessInfo{PID: pid, Arch: "x86_64", PointerSize: 8}, nil
			},
			sessionByID: map[int]*fakeFridaStream{5001: stream},
		}
		tracer := newWindowsAPITracerWithConfig(nil, 16, driver)
		defer tracer.Stop()
		err := tracer.Attach(context.Background(), 5001)
		if !errors.Is(err, errAPITracingUnavailable) || !errors.Is(err, errFridaABIMismatch) {
			t.Fatalf("expected errFridaABIMismatch on pointer_size mismatch, got %v", err)
		}
	})

	t.Run("target exit before handshake", func(t *testing.T) {
		pr, pw := io.Pipe()
		_ = pw.Close() // Immediate EOF before FRIDA_SESSION ready
		stream := &fakeFridaStream{pr: pr, pw: pw}
		driver := &fakeFridaDriver{
			sessionByID: map[int]*fakeFridaStream{5002: stream},
		}
		tracer := newWindowsAPITracerWithConfig(nil, 16, driver)
		defer tracer.Stop()
		err := tracer.Attach(context.Background(), 5002)
		if !errors.Is(err, errAPITracingUnavailable) || !errors.Is(err, errTargetProcessExited) {
			t.Fatalf("expected errTargetProcessExited on pre-ready EOF, got %v", err)
		}
	})

	t.Run("bounded channel backpressure and unsupported category gap", func(t *testing.T) {
		lines := []string{
			`FRIDA_SESSION {"type":"ready","pid":5003,"arch":"x64","pointer_size":8,"hooked":["kernel32.dll!VirtualAllocEx"],"gaps":[{"category":"Memory","module":"ntdll.dll","function":"NtAllocateVirtualMemory","reason":"export missing"}]}`,
		}
		for i := 0; i < 10; i++ {
			lines = append(lines, fmt.Sprintf(
				`FRIDA_API {"ts":%d,"pid":5003,"tid":5004,"cat":"Memory","mod":"kernel32.dll","fn":"VirtualAllocEx","params":[{"name":"hProcess","type":"HANDLE","value":"0x100"}],"ret":"0x20000","err":0}`,
				1700000000000+i,
			))
		}
		stream := newFakeFridaStream(lines...)
		driver := &fakeFridaDriver{
			sessionByID: map[int]*fakeFridaStream{5003: stream},
		}
		// Channel capacity 3 + 1 unsupported category
		tracer := newWindowsAPITracerWithConfig([]string{CategoryMemory, "KernelETW"}, 3, driver)
		if err := tracer.Attach(context.Background(), 5003); err != nil {
			t.Fatalf("Attach failed: %v", err)
		}

		// Wait until at least 7 calls are dropped because nothing is reading tracer.Calls() yet.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && tracer.DroppedCalls() < 7 {
			time.Sleep(10 * time.Millisecond)
		}
		if got := tracer.DroppedCalls(); got != 7 {
			t.Fatalf("expected 7 dropped calls with cap=3 and 10 sent, got %d", got)
		}

		if err := tracer.Detach(5003); err != nil {
			t.Fatalf("Detach failed: %v", err)
		}
		if err := tracer.Stop(); err != nil {
			t.Fatalf("Stop failed: %v", err)
		}

		var drained int
		for range tracer.Calls() {
			drained++
		}
		if drained != 3 {
			t.Fatalf("expected 3 buffered calls drained after Stop, got %d", drained)
		}

		statuses := tracer.DegradedStatuses()
		hasGap := false
		hasHookGap := false
		hasBackpressure := false
		for _, s := range statuses {
			if s.Phase == "coverage_gap" && strings.Contains(s.Reason, "KernelETW") {
				hasGap = true
			}
			if s.Phase == "hook_gap" && strings.Contains(s.Reason, "NtAllocateVirtualMemory") {
				hasHookGap = true
			}
			if s.Phase == "backpressure" && strings.Contains(s.Reason, "dropped 7 API calls") {
				hasBackpressure = true
			}
		}
		if !hasGap || !hasHookGap || !hasBackpressure {
			t.Fatalf("expected coverage_gap, hook_gap, and backpressure statuses, got %+v", statuses)
		}
	})
}
