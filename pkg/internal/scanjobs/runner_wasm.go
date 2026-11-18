//go:build wasm

package scanjobs

import "os/exec"

// os/exec cannot start processes in WebAssembly. The browser command adapter
// runs the analyzer directly and cancels it by terminating its Web Worker.
func killProcessTree(cmd *exec.Cmd) {}
