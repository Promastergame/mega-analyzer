//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// setDetachedProcess detaches the child process from this console so the GUI
// editor does not pin a terminal window (Windows-only DETACHED_PROCESS).
func setDetachedProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008, // DETACHED_PROCESS
	}
}
