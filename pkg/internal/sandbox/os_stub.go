//go:build !windows

package sandbox

import (
	"fmt"
	"os/exec"
)

func prepareCommand(cmd *exec.Cmd) {}

func resumeProcess(pid int) error {
	return fmt.Errorf("sandbox mode is supported on Windows only")
}

func applyCPUAffinity(pid, cores int) error { return nil }

func newProcessGuard(maxMemoryMB int) (processGuard, error) {
	return nil, fmt.Errorf("sandbox mode is supported on Windows only")
}

func newBlockingNetworkGuard(exePath, sessionID string) (networkGuard, error) {
	return nil, fmt.Errorf("sandbox mode is supported on Windows only")
}

func collectSnapshot(rootPID int) ([]ObservedProcess, []ObservedConnection, error) {
	return nil, nil, fmt.Errorf("sandbox mode is supported on Windows only")
}

func captureAutorunSnapshot() (map[string]RegistryValue, error) {
	return nil, fmt.Errorf("sandbox mode is supported on Windows only")
}

func enrichObservedProcesses(processes []ObservedProcess) []ObservedProcess {
	return processes
}

func checkPrivileges() error {
	return fmt.Errorf("sandbox enhancements are supported on Windows only")
}

func isAdmin() bool { return false }
