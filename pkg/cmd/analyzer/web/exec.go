package web

import (
	"context"
	"fmt"
	"mega-analyzer/pkg/internal/platformtext"
	"os/exec"
	"time"
)

func runToolBounded(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	prepareProbeCommand(cmd)
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s timed out: %w", name, ctx.Err())
	}
	return platformtext.DecodeConsoleOutput(out), err
}
