package main

import (
	"fmt"

	"mega-analyzer/pkg/api"
	"mega-analyzer/pkg/binzap"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/vulnscan"
)

// handleAPIServer starts the REST API from the unified analyzer executable.
// Dynamic registries are preloaded exactly as they were by cmd/analyzer-api.
func (a *App) handleAPIServer() error {
	a.output.Info("══════ Mega-Analyzer REST API ══════")

	if err := vulnscan.LoadDynamicWebRules(); err != nil {
		a.output.Warning("Failed to load dynamic web rules: %v", err)
	} else {
		a.output.Info("Loaded %d dynamic web rule(s)", len(vulnscan.GetDynamicWebRules()))
	}
	if err := binzap.LoadDynamicBinzapRules(); err != nil {
		a.output.Warning("Failed to load dynamic BinZAP rules: %v", err)
	} else {
		a.output.Info("Loaded %d dynamic BinZAP rule(s)", len(binzap.GetRawDynamicBinzapRules()))
	}
	if err := ml.LoadDynamicMLPatterns(); err != nil {
		a.output.Warning("Failed to load dynamic ML patterns: %v", err)
	} else {
		a.output.Info("Loaded %d dynamic ML pattern(s)", len(ml.GetDynamicMLPatterns()))
	}

	a.output.Success("REST API listening on port %d", a.opts.APIPort)
	server := api.NewAPIServer(a.opts.APIPort)
	if err := server.Start(); err != nil {
		return fmt.Errorf("API server: %w", err)
	}
	return nil
}
