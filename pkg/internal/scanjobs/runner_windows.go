//go:build windows

package scanjobs

import (
	"os/exec"
	"strconv"
	"syscall"
)

// killProcessTree uses taskkill /T so the timed-out analyzer's children die
// with it. exec.CommandContext on Windows otherwise kills only the direct
// process.
func killProcessTree(cmd *exec.Cmd) {
	exe, lookErr := exec.LookPath("taskkill.exe")
	if lookErr != nil {
		return
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		kill := exec.Command(exe, "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
		kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = kill.Run()
		return nil
	}
}
