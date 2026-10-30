package sandbox

import (
	"context"
	"errors"
	"fmt"
	"runtime"
)

// ExecutionError is an engine/setup failure, never a behavioural detection.
// The stable code survives localisation and is shared with the dashboard.
type ExecutionError struct {
	Code  string
	Stage string
	Cause error
}

func (e *ExecutionError) Error() string {
	if e.Cause == nil {
		return e.Code
	}
	return e.Cause.Error()
}
func (e *ExecutionError) Unwrap() error { return e.Cause }

type ExecutionFailure struct {
	Code    string `json:"code"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

func DescribeFailure(err error) *ExecutionFailure {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return &ExecutionFailure{Code: "canceled", Stage: "stopping", Message: "The sandbox session was canceled."}
	}
	var runErr *ExecutionError
	if errors.As(err, &runErr) {
		return &ExecutionFailure{Code: runErr.Code, Stage: runErr.Stage, Message: runErr.Error()}
	}
	return &ExecutionFailure{Code: "engine_failed", Stage: "execution", Message: err.Error()}
}
func executionError(code, stage string, err error) error {
	return &ExecutionError{Code: code, Stage: stage, Cause: err}
}

// NativeReadiness does not elevate the process or change firewall settings.
// A native host is explicitly not represented as a virtual machine.
type NativeReadiness struct {
	Supported                        bool   `json:"supported"`
	Elevated                         bool   `json:"elevated"`
	RequiresAdminForNetworkIsolation bool   `json:"requiresAdminForNetworkIsolation"`
	Isolation                        string `json:"isolation"`
}

func NativeSandboxReadiness() NativeReadiness {
	return NativeReadiness{Supported: runtime.GOOS == "windows", Elevated: isAdmin(), RequiresAdminForNetworkIsolation: true, Isolation: "native_os"}
}
func checkNetworkIsolationPrivilege(blockNetwork, elevated bool) error {
	if blockNetwork && !elevated {
		return executionError("admin_required", "preflight", fmt.Errorf("Windows network isolation requires an elevated analyzer process. Run the analyzer as administrator only on a disposable analysis host. The sample has not been started; network isolation has not been bypassed."))
	}
	return nil
}
