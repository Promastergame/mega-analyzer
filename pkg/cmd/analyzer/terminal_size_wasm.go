//go:build wasm

package main

// Browser analysis has no terminal; the CLI uses its noninteractive layout.
func terminalSize() (int, int) { return 120, 40 }
