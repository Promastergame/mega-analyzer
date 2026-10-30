//go:build !windows

package web

import "os/exec"

func prepareProbeCommand(cmd *exec.Cmd) {}
