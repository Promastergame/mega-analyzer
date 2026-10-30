//go:build legacy_fuzzer
// +build legacy_fuzzer

package main

import (
	"fmt"
	"path/filepath"

	"mega-analyzer/pkg/binzap"
)

func runActiveFuzzer(activeFuzz, configPath, outputDir string) error {
	cfg, err := binzap.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("[!] Warning: Could not load config %s, using defaults: %v\n", configPath, err)
	}

	fuzzer := binzap.NewActiveFuzzer(cfg)
	findings, err := fuzzer.FuzzMethod(activeFuzz)
	if err != nil {
		return err
	}

	safeSigName := filepath.Base(activeFuzz)
	if err := binzap.GenerateFullReport(findings, outputDir, "ACTIVE_FUZZ_"+safeSigName); err != nil {
		return fmt.Errorf("generate report: %w", err)
	}
	fmt.Printf("[+] Active Fuzzing completed. Found %d issues.\n", len(findings))
	return nil
}
