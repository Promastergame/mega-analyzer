//go:build windows

package web

import (
	"os/exec"
	"syscall"
)

func prepareProbeCommand(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
