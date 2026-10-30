//go:build !windows

package main

import (
	"os/exec"
)

// setDetachedProcess is a no-op on non-Windows platforms: POSIX children do
// not inherit a console in a way that needs suppression here.
func setDetachedProcess(cmd *exec.Cmd) {
	_ = cmd
}
