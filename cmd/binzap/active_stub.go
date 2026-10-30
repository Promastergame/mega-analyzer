//go:build !legacy_fuzzer
// +build !legacy_fuzzer

package main

import "fmt"

func runActiveFuzzer(activeFuzz, configPath, outputDir string) error {
	return fmt.Errorf("active fuzzer is quarantined/legacy and requires building with '-tags legacy_fuzzer'")
}
