//go:build windows

package sandbox

import (
	"fmt"
)

// windowsAntiSandboxDetector implements AntiSandboxDetector for Windows.
type windowsAntiSandboxDetector struct{}

func newAntiSandboxDetector() AntiSandboxDetector {
	return &windowsAntiSandboxDetector{}
}

// Analyze examines API calls and events to detect anti-sandbox techniques.
//
// Validates: Requirements 8.1, 8.2, 8.3
func (d *windowsAntiSandboxDetector) Analyze(apiCalls []APICall, kernelEvents []KernelEvent) []AntiSandboxTechnique {
	techniques := []AntiSandboxTechnique{}

	// Detect debugger checks
	techniques = append(techniques, d.DetectDebuggerChecks(apiCalls)...)

	// Detect VM checks
	techniques = append(techniques, d.DetectVMChecks(apiCalls, kernelEvents)...)

	// Detect timing checks
	techniques = append(techniques, d.DetectTimingChecks(apiCalls)...)

	return techniques
}

// DetectDebuggerChecks identifies debugger detection attempts.
//
// Validates: Requirement 8.1
func (d *windowsAntiSandboxDetector) DetectDebuggerChecks(apiCalls []APICall) []AntiSandboxTechnique {
	techniques := []AntiSandboxTechnique{}

	for _, call := range apiCalls {
		if IsDebuggerAPI(call.Function) {
			technique := CreateAntiSandboxTechnique(
				TechniqueDebuggerCheck,
				fmt.Sprintf("Debugger detection via %s", call.Function),
				call.Timestamp,
				call.ProcessID,
				map[string]string{
					"function": call.Function,
					"module":   call.Module,
				},
			)
			techniques = append(techniques, technique)
		}
	}

	return techniques
}

// DetectVMChecks identifies VM artifact checks.
//
// Validates: Requirement 8.2
func (d *windowsAntiSandboxDetector) DetectVMChecks(apiCalls []APICall, kernelEvents []KernelEvent) []AntiSandboxTechnique {
	techniques := []AntiSandboxTechnique{}

	// Check for VM artifact file access in kernel events
	for _, event := range kernelEvents {
		if event.EventType == EventFileCreate && IsVMArtifact(event.Path) {
			technique := CreateAntiSandboxTechnique(
				TechniqueVMCheck,
				fmt.Sprintf("VM artifact check: %s", event.Path),
				event.Timestamp,
				event.ProcessID,
				map[string]string{
					"path":      event.Path,
					"operation": event.Operation,
				},
			)
			techniques = append(techniques, technique)
		}
	}

	// Check for VM artifact checks in API calls
	for _, call := range apiCalls {
		if call.Function == "CreateFileA" || call.Function == "CreateFileW" {
			for _, param := range call.Parameters {
				if param.Name == "lpFileName" && IsVMArtifact(param.Value) {
					technique := CreateAntiSandboxTechnique(
						TechniqueVMCheck,
						fmt.Sprintf("VM artifact check via API: %s", param.Value),
						call.Timestamp,
						call.ProcessID,
						map[string]string{
							"function": call.Function,
							"path":     param.Value,
						},
					)
					techniques = append(techniques, technique)
				}
			}
		}
	}

	return techniques
}

// DetectTimingChecks identifies timing-based evasion.
//
// Validates: Requirement 8.3
func (d *windowsAntiSandboxDetector) DetectTimingChecks(apiCalls []APICall) []AntiSandboxTechnique {
	techniques := []AntiSandboxTechnique{}

	// Track timing API calls to detect suspicious patterns
	timingCallCount := 0
	var firstTimingCall *APICall

	for i := range apiCalls {
		call := &apiCalls[i]
		if IsTimingAPI(call.Function) {
			timingCallCount++
			if firstTimingCall == nil {
				firstTimingCall = call
			}

			// If we see multiple timing calls in quick succession, it's suspicious
			if timingCallCount >= 3 && firstTimingCall != nil {
				elapsed := call.Timestamp.Sub(firstTimingCall.Timestamp)
				if elapsed.Seconds() < 1.0 {
					technique := CreateAntiSandboxTechnique(
						TechniqueTimingCheck,
						fmt.Sprintf("Timing check pattern detected (%d calls in %v)", timingCallCount, elapsed),
						call.Timestamp,
						call.ProcessID,
						map[string]string{
							"function":   call.Function,
							"call_count": fmt.Sprintf("%d", timingCallCount),
							"elapsed_ms": fmt.Sprintf("%.0f", elapsed.Seconds()*1000),
						},
					)
					techniques = append(techniques, technique)

					// Reset counters
					timingCallCount = 0
					firstTimingCall = nil
				}
			}
		}
	}

	// Check for hardware checks (disk size, memory size)
	for _, call := range apiCalls {
		if IsHardwareAPI(call.Function) {
			technique := CreateAntiSandboxTechnique(
				TechniqueHardwareCheck,
				fmt.Sprintf("Hardware check via %s", call.Function),
				call.Timestamp,
				call.ProcessID,
				map[string]string{
					"function": call.Function,
					"module":   call.Module,
				},
			)
			techniques = append(techniques, technique)
		}
	}

	return techniques
}
