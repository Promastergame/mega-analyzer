package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
)

func (a *App) handleRemoteSandbox() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	output := a.opts.SandboxOutput
	if output == "" {
		output = a.opts.Output
	}
	a.output.Info("VM execution; reports and keys are stored on THIS PC")
	a.output.Info("Guest target: %s", a.opts.Target)
	a.output.Warning("VM network isolation, memory limits and snapshots must be configured in the hypervisor. Remote capture stops gated children; descendant behavior is not observed.")
	r, err := sandbox.RunRemote(ctx, sandbox.RemoteOptions{ProfilePath: a.opts.SandboxRemoteConfig, Target: a.opts.Target, OutputDir: output, Duration: time.Duration(a.opts.SandboxDuration) * time.Second})
	if r != nil {
		a.output.Info("Host JSON report: %s", r.JSONPath)
		a.output.Info("Host Markdown report: %s", r.MarkdownPath)
		a.output.Info("Durable host journal: %s", r.RemoteCapture.JournalPath)
		a.output.Info("Captured key/IV records: %d; incomplete: %t", len(r.CryptoAnalysis.Materials), r.RemoteCapture.Incomplete)
	}
	return err
}
