//go:build !windows

package sandbox

// stubAntiSandboxDetector is a no-op implementation for non-Windows platforms.
type stubAntiSandboxDetector struct{}

func newAntiSandboxDetector() AntiSandboxDetector {
	return &stubAntiSandboxDetector{}
}

func (d *stubAntiSandboxDetector) Analyze(apiCalls []APICall, kernelEvents []KernelEvent) []AntiSandboxTechnique {
	return []AntiSandboxTechnique{}
}

func (d *stubAntiSandboxDetector) DetectDebuggerChecks(apiCalls []APICall) []AntiSandboxTechnique {
	return []AntiSandboxTechnique{}
}

func (d *stubAntiSandboxDetector) DetectVMChecks(apiCalls []APICall, kernelEvents []KernelEvent) []AntiSandboxTechnique {
	return []AntiSandboxTechnique{}
}

func (d *stubAntiSandboxDetector) DetectTimingChecks(apiCalls []APICall) []AntiSandboxTechnique {
	return []AntiSandboxTechnique{}
}
