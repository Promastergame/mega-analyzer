//go:build !windows

package netproxy

import "fmt"

// RustMITMEngine is a portable stub for the Windows Rust MITM DLL bridge.
type RustMITMEngine struct{}

var engine *RustMITMEngine

func InitRustMITM(dllPath string) error {
	return fmt.Errorf("Rust MITM DLL loading is supported on Windows only")
}
func GenerateRootCA(outDir string) error {
	return fmt.Errorf("Rust MITM engine is supported on Windows only")
}
func StartDNSSpoof(listenAddr, targetDomain, spoofedIP string) error {
	return fmt.Errorf("Rust MITM engine is supported on Windows only")
}
func StartDHCPSpoof(listenAddr, gatewayIP string) error {
	return fmt.Errorf("Rust MITM engine is supported on Windows only")
}
func StartSSLStrip(listenAddr string) error {
	return fmt.Errorf("Rust MITM engine is supported on Windows only")
}
func StartObfsProxy(listenAddr, upstreamAddr string, key [32]byte) error {
	return fmt.Errorf("Rust MITM engine is supported on Windows only")
}
