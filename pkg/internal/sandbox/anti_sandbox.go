package sandbox

import (
	"time"
)

// AntiSandboxDetector identifies anti-sandbox and anti-debug evasion techniques.
//
// Validates: Requirements 8.1, 8.2, 8.3, 8.4
type AntiSandboxDetector interface {
	// Analyze examines API calls and events to detect anti-sandbox techniques
	Analyze(apiCalls []APICall, kernelEvents []KernelEvent) []AntiSandboxTechnique

	// DetectDebuggerChecks identifies debugger detection attempts
	DetectDebuggerChecks(apiCalls []APICall) []AntiSandboxTechnique

	// DetectVMChecks identifies VM artifact checks
	DetectVMChecks(apiCalls []APICall, kernelEvents []KernelEvent) []AntiSandboxTechnique

	// DetectTimingChecks identifies timing-based evasion
	DetectTimingChecks(apiCalls []APICall) []AntiSandboxTechnique
}

// NewAntiSandboxDetector creates a new anti-sandbox detector.
func NewAntiSandboxDetector() AntiSandboxDetector {
	return newAntiSandboxDetector()
}

// Anti-sandbox technique types
const (
	TechniqueDebuggerCheck = "DebuggerCheck"
	TechniqueVMCheck       = "VMCheck"
	TechniqueTimingCheck   = "TimingCheck"
	TechniqueHardwareCheck = "HardwareCheck"
	TechniqueSandboxCheck  = "SandboxCheck"
)

// Known VM artifacts
var vmArtifacts = []string{
	"VBoxGuest.sys",
	"VBoxMouse.sys",
	"VBoxSF.sys",
	"vmtoolsd.exe",
	"vmware.exe",
	"vmmouse.sys",
	"vmusrvc.exe",
	"qemu-ga.exe",
	"prl_tools.exe",
}

// Known debugger detection APIs
var debuggerAPIs = []string{
	"IsDebuggerPresent",
	"CheckRemoteDebuggerPresent",
	"NtQueryInformationProcess",
	"OutputDebugStringA",
	"OutputDebugStringW",
}

// Known timing check APIs
var timingAPIs = []string{
	"GetTickCount",
	"GetTickCount64",
	"QueryPerformanceCounter",
	"timeGetTime",
	"GetSystemTime",
}

// Known hardware check APIs
var hardwareAPIs = []string{
	"GetSystemInfo",
	"GlobalMemoryStatusEx",
	"GetDiskFreeSpaceExA",
	"GetDiskFreeSpaceExW",
}

// IsDebuggerAPI checks if an API is used for debugger detection.
func IsDebuggerAPI(function string) bool {
	for _, api := range debuggerAPIs {
		if function == api {
			return true
		}
	}
	return false
}

// IsTimingAPI checks if an API is used for timing checks.
func IsTimingAPI(function string) bool {
	for _, api := range timingAPIs {
		if function == api {
			return true
		}
	}
	return false
}

// IsHardwareAPI checks if an API is used for hardware checks.
func IsHardwareAPI(function string) bool {
	for _, api := range hardwareAPIs {
		if function == api {
			return true
		}
	}
	return false
}

// IsVMArtifact checks if a path references a known VM artifact.
func IsVMArtifact(path string) bool {
	for _, artifact := range vmArtifacts {
		if containsIgnoreCase(path, artifact) {
			return true
		}
	}
	return false
}

// containsIgnoreCase checks if s contains substr (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return containsSubstr(s, substr)
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && indexOfSubstring(s, substr) >= 0
}

func indexOfSubstring(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// CreateAntiSandboxTechnique creates a new anti-sandbox technique record.
func CreateAntiSandboxTechnique(techType, description string, timestamp time.Time, processID int, details map[string]string) AntiSandboxTechnique {
	return AntiSandboxTechnique{
		Type:        techType,
		Description: description,
		Timestamp:   timestamp,
		ProcessID:   processID,
		Details:     details,
	}
}
