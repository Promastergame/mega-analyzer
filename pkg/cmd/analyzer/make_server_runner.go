package main

import (
	"fmt"
	"path/filepath"

	"mega-analyzer/pkg/internal/privserver"
)

// handleMakeServer runs the authorized-lab Elixir/OTP private server
// generator pipeline: discover → plan → generate skeleton → write reports.
func (a *App) handleMakeServer() error {
	a.output.Info("══════ Make-Server: Authorized-Lab Private Server Generator ══════")
	a.output.Info("Target: %s", a.opts.Target)

	// 1. Discover
	discOpts := privserver.DiscoverOptions{
		GameName:   a.opts.MakeServerGame,
		Module:     a.opts.MakeServerModule,
		ListenPort: a.opts.MakeServerPort,
		AdminPort:  a.opts.MakeServerAdmin,
	}

	a.output.Info("Scanning target for endpoints, transport hints, SSL pinning...")
	plan, err := privserver.Discover(a.opts.Target, discOpts)
	if err != nil {
		return fmt.Errorf("make-server discovery failed: %w", err)
	}

	a.output.Success("Discovery complete: family=%s transport=%s framing=%s",
		plan.Family, plan.Transport.Protocol, plan.Framing.Style)
	a.output.Info("  Endpoints: %d | Domains: %d | IPs: %d",
		len(plan.Endpoints), len(plan.Domains), len(plan.IPs))
	a.output.Info("  Messages: %d | Replays: %d | Readiness: %d/100 (%s)",
		len(plan.Messages), len(plan.Replays), plan.Readiness.Score, plan.Readiness.Risk)

	if plan.Pinning.Detected {
		a.output.Warning("SSL pinning detected — clients will refuse the mock server until pinning is bypassed")
	}

	// 2. Determine output paths
	outDir := a.opts.Output
	if outDir == "" {
		outDir = "analysis_output"
	}

	serverDir := a.opts.MakeServerOutput
	if serverDir == "" {
		serverDir = filepath.Join(outDir, "private_server")
	}

	// 3. Generate Elixir/OTP skeleton
	a.output.Info("Generating Elixir/OTP skeleton → %s", serverDir)
	projectRoot, err := privserver.Generate(plan, serverDir)
	if err != nil {
		return fmt.Errorf("make-server generation failed: %w", err)
	}
	a.output.Success("Elixir project generated: %s", projectRoot)

	// 4. Write plan JSON and readiness report
	if err := privserver.WritePlan(plan, outDir); err != nil {
		a.output.Warning("Failed to write plan JSON: %v", err)
	} else {
		a.output.Info("Plan written: %s", filepath.Join(outDir, "private_server_plan.json"))
	}

	if err := privserver.WriteReadiness(plan, outDir); err != nil {
		a.output.Warning("Failed to write readiness report: %v", err)
	} else {
		a.output.Info("Readiness report: %s", filepath.Join(outDir, "PRIVATE_SERVER_READINESS.md"))
	}

	// 5. Summary
	a.output.Info("")
	a.output.Info("────────────────────────────────────────────────────────────")
	a.output.Success("Make-Server complete!")
	a.output.Info("  Game:      %s", plan.GameName)
	a.output.Info("  Module:    %s", plan.Module)
	a.output.Info("  Transport: %s (TLS: %v)", plan.Transport.Protocol, plan.Transport.UsesTLS)
	a.output.Info("  Listen:    %s:%d (admin: %d)", plan.Listen.Host, plan.Listen.Port, plan.Listen.AdminPort)
	a.output.Info("  Score:     %d/100 (%s)", plan.Readiness.Score, plan.Readiness.Risk)
	a.output.Info("")
	a.output.Info("To run the generated server:")
	a.output.Info("  cd %s", projectRoot)
	a.output.Info("  mix deps.get")
	a.output.Info("  mix run --no-halt")
	a.output.Info("")
	a.output.Info("Admin dashboard: http://localhost:%d", plan.Listen.AdminPort)
	a.output.Info("────────────────────────────────────────────────────────────")

	return nil
}
