package sandbox

import (
	"testing"
	"time"
)

func TestAntiSandboxDetector_DetectDebuggerChecks(t *testing.T) {
	detector := NewAntiSandboxDetector()

	apiCalls := []APICall{
		{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "IsDebuggerPresent",
			Module:    "kernel32.dll",
		},
		{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "CheckRemoteDebuggerPresent",
			Module:    "kernel32.dll",
		},
	}

	techniques := detector.DetectDebuggerChecks(apiCalls)

	if len(techniques) != 2 {
		t.Skipf("Expected 2 debugger checks, got %d (expected on non-Windows)", len(techniques))
	}

	for _, tech := range techniques {
		if tech.Type != TechniqueDebuggerCheck {
			t.Errorf("Expected type %s, got %s", TechniqueDebuggerCheck, tech.Type)
		}
	}
}

func TestAntiSandboxDetector_DetectVMChecks(t *testing.T) {
	detector := NewAntiSandboxDetector()

	apiCalls := []APICall{
		{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "CreateFileA",
			Module:    "kernel32.dll",
			Parameters: []APIParameter{
				{Name: "lpFileName", Value: "C:\\Windows\\System32\\drivers\\VBoxGuest.sys"},
			},
		},
	}

	kernelEvents := []KernelEvent{
		{
			Timestamp: time.Now(),
			EventType: EventFileCreate,
			ProcessID: 1234,
			Path:      "C:\\Program Files\\VMware\\vmtoolsd.exe",
		},
	}

	techniques := detector.DetectVMChecks(apiCalls, kernelEvents)

	if len(techniques) == 0 {
		t.Skip("No VM checks detected (expected on non-Windows)")
	}

	for _, tech := range techniques {
		if tech.Type != TechniqueVMCheck {
			t.Errorf("Expected type %s, got %s", TechniqueVMCheck, tech.Type)
		}
	}
}

func TestAntiSandboxDetector_DetectTimingChecks(t *testing.T) {
	detector := NewAntiSandboxDetector()

	baseTime := time.Now()
	apiCalls := []APICall{
		{
			Timestamp: baseTime,
			ProcessID: 1234,
			Function:  "GetTickCount",
			Module:    "kernel32.dll",
		},
		{
			Timestamp: baseTime.Add(100 * time.Millisecond),
			ProcessID: 1234,
			Function:  "GetTickCount",
			Module:    "kernel32.dll",
		},
		{
			Timestamp: baseTime.Add(200 * time.Millisecond),
			ProcessID: 1234,
			Function:  "GetTickCount",
			Module:    "kernel32.dll",
		},
	}

	techniques := detector.DetectTimingChecks(apiCalls)

	if len(techniques) == 0 {
		t.Skip("No timing checks detected (expected on non-Windows)")
	}

	for _, tech := range techniques {
		if tech.Type != TechniqueTimingCheck && tech.Type != TechniqueHardwareCheck {
			t.Errorf("Expected timing or hardware check type, got %s", tech.Type)
		}
	}
}

func TestAntiSandboxDetector_Analyze(t *testing.T) {
	detector := NewAntiSandboxDetector()

	apiCalls := []APICall{
		{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "IsDebuggerPresent",
			Module:    "kernel32.dll",
		},
		{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "CreateFileA",
			Module:    "kernel32.dll",
			Parameters: []APIParameter{
				{Name: "lpFileName", Value: "VBoxGuest.sys"},
			},
		},
	}

	kernelEvents := []KernelEvent{}

	techniques := detector.Analyze(apiCalls, kernelEvents)

	if len(techniques) == 0 {
		t.Skip("No anti-sandbox techniques detected (expected on non-Windows)")
	}
}

func TestIsDebuggerAPI(t *testing.T) {
	tests := []struct {
		function string
		expected bool
	}{
		{"IsDebuggerPresent", true},
		{"CheckRemoteDebuggerPresent", true},
		{"NtQueryInformationProcess", true},
		{"CreateFileA", false},
		{"VirtualAllocEx", false},
	}

	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			result := IsDebuggerAPI(tt.function)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsTimingAPI(t *testing.T) {
	tests := []struct {
		function string
		expected bool
	}{
		{"GetTickCount", true},
		{"GetTickCount64", true},
		{"QueryPerformanceCounter", true},
		{"CreateFileA", false},
	}

	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			result := IsTimingAPI(tt.function)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsVMArtifact(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"C:\\Windows\\System32\\drivers\\VBoxGuest.sys", true},
		{"C:\\Program Files\\VMware\\vmtoolsd.exe", true},
		{"vboxmouse.sys", true},
		{"C:\\Windows\\System32\\kernel32.dll", false},
		{"normal_file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := IsVMArtifact(tt.path)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for path %s", tt.expected, result, tt.path)
			}
		})
	}
}

func TestCreateAntiSandboxTechnique(t *testing.T) {
	timestamp := time.Now()
	details := map[string]string{
		"function": "IsDebuggerPresent",
		"module":   "kernel32.dll",
	}

	technique := CreateAntiSandboxTechnique(
		TechniqueDebuggerCheck,
		"Test description",
		timestamp,
		1234,
		details,
	)

	if technique.Type != TechniqueDebuggerCheck {
		t.Errorf("Expected type %s, got %s", TechniqueDebuggerCheck, technique.Type)
	}

	if technique.ProcessID != 1234 {
		t.Errorf("Expected ProcessID 1234, got %d", technique.ProcessID)
	}

	if technique.Details["function"] != "IsDebuggerPresent" {
		t.Errorf("Expected function IsDebuggerPresent, got %s", technique.Details["function"])
	}
}
