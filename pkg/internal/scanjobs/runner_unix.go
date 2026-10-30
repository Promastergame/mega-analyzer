//go:build unix

package scanjobs

import (
	"context"
	"os/exec"
	"syscall"
)

// killProcessTree arranges for cmd's cancellation to terminate the whole
// process group, not just the direct child, so spawned helpers cannot
// outlive the job's context while still holding its pipes.
func killProcessTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return context.Canceled
	}
}
