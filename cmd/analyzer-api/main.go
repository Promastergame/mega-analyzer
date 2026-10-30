package main

import (
	"flag"
	"os"

	"mega-analyzer/pkg/api"
	"mega-analyzer/pkg/binzap"
	"mega-analyzer/pkg/logger"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/vulnscan"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	logger.Info("=================================================================")
	logger.Info("🛡️  Mega-Analyzer — Unified Dynamic API Server")
	logger.Info("=================================================================")

	fs := flag.NewFlagSet("analyzer-api", flag.ContinueOnError)
	port := fs.Int("port", 5000, "Port to run the API server on")

	if len(args) > 0 && args[0] == "-test-run-only" {
		return 0
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}

	logger.Info("[*] Pre-loading dynamic analyzer registries...")

	if err := vulnscan.LoadDynamicWebRules(); err != nil {
		logger.Warn("Failed to load dynamic web rules", "error", err)
	} else {
		logger.Info("Loaded dynamic web scanner rules", "count", len(vulnscan.GetDynamicWebRules()))
	}

	if err := binzap.LoadDynamicBinzapRules(); err != nil {
		logger.Warn("Failed to load dynamic binzap rules", "error", err)
	} else {
		logger.Info("Loaded dynamic binzap bytecode rules", "count", len(binzap.GetRawDynamicBinzapRules()))
	}

	if err := ml.LoadDynamicMLPatterns(); err != nil {
		logger.Warn("Failed to load dynamic ML patterns", "error", err)
	} else {
		logger.Info("Loaded dynamic ML Smali patterns", "count", len(ml.GetDynamicMLPatterns()))
	}

	server := api.NewAPIServer(*port)
	if err := server.Start(); err != nil {
		logger.Error("API Server execution error", "error", err)
		return 1
	}
	return 0
}
