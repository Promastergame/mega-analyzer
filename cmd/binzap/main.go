package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"mega-analyzer/pkg/binzap"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fmt.Println("--- BinZAP: Binary Passive/Active Scanner ---")

	// CLI flags
	fs := flag.NewFlagSet("binzap", flag.ContinueOnError)
	targetFile := fs.String("file", "", "Path to a specific file to scan (.smali or .asm)")
	targetPE := fs.String("pe", "", "Path to a native binary to scan (PE/ELF/Mach-O, incl. .NET assemblies)")
	targetDir := fs.String("dir", "", "Path to a directory to recursively scan")
	targetAPK := fs.String("apk", "", "Path to an APK file to unpack and scan")
	outputDir := fs.String("output", "binzap_reports", "Directory to save reports")
	activeFuzz := fs.String("active", "", "Run active fuzzer against specific method signature")
	configPath := fs.String("config", "binzap.json", "Path to sandbox config file")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}

	// 1. Handle Active Fuzzer Execution
	if *activeFuzz != "" {
		if err := runActiveFuzzer(*activeFuzz, *configPath, *outputDir); err != nil {
			fmt.Printf("[-] Active Fuzzer error: %v\n", err)
			return 1
		}
		return 0
	}

	// 2. Handle APK Unpacking & Scanning
	if *targetAPK != "" {
		fmt.Printf("[*] Unpacking APK using mega-analyzer/apkloader: %s\n", *targetAPK)

		ctx := context.Background()

		unpackedDir, err := binzap.UnpackAPK(ctx, *targetAPK)
		if err != nil {
			fmt.Printf("[-] Failed to unpack APK: %v\n", err)
			return 1
		}

		fmt.Printf("[+] APK Unpacked to: %s\n", unpackedDir)
		fmt.Println("[*] Running passive scan across all decompiled files...")

		findings, err := binzap.RunPassiveDirectory(unpackedDir)
		if err != nil {
			fmt.Printf("[-] Failed to scan unpacked APK directory: %v\n", err)
			return 1
		}

		baseName := filepath.Base(*targetAPK)
		binzap.GenerateFullReport(findings, *outputDir, baseName)
		fmt.Printf("[+] APK Scan complete. Found %d issues.\n", len(findings))
		return 0
	}

	// 3. Handle Directory Scan
	if *targetDir != "" {
		fmt.Printf("[*] Scanning directory recursively: %s\n", *targetDir)
		findings, err := binzap.RunPassiveDirectory(*targetDir)
		if err != nil {
			fmt.Printf("[-] Failed to scan directory: %v\n", err)
			return 1
		}

		baseName := filepath.Base(*targetDir)
		binzap.GenerateFullReport(findings, *outputDir, baseName)
		fmt.Printf("[+] Directory scan complete. Found %d issues.\n", len(findings))
		return 0
	}

	// 4. Handle Native Binary Scan (PE/ELF/Mach-O, incl. .NET)
	if *targetPE != "" {
		fmt.Printf("[*] Scanning native binary: %s\n", *targetPE)
		report, err := binzap.ScanNativeFile(*targetPE)
		if err != nil {
			fmt.Printf("[-] Failed to scan binary: %v\n", err)
			return 1
		}
		fmt.Println(report)
		return 0
	}

	// 5. Handle Single File Scan
	if *targetFile != "" {
		fmt.Printf("[*] Scanning single file: %s\n", *targetFile)
		findings, err := binzap.RunPassiveFile(*targetFile)
		if err != nil {
			fmt.Printf("[-] Failed to scan file: %v\n", err)
			return 1
		}

		baseName := filepath.Base(*targetFile)
		binzap.GenerateFullReport(findings, *outputDir, baseName)
		fmt.Printf("[+] File scan complete. Found %d issues.\n", len(findings))
		return 0
	}

	// If no valid flags passed
	fmt.Println("Usage:")
	fs.Usage()
	return 1
}
