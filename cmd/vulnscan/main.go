package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"mega-analyzer/pkg/vulnscan"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fmt.Println("=====================================================")
	fmt.Println(" Mega-Analyzer: Active Web Vulnerability Scanner")
	fmt.Println("=====================================================")

	fs := flag.NewFlagSet("vulnscan", flag.ContinueOnError)
	// ── Core flags ────────────────────────────────────────────────────────────
	targetURL := fs.String("target", "", "Target URL to actively scan (e.g. http://127.0.0.1:3000)")
	webMode := fs.String("mode", "active", "Web scan mode: status (one GET), passive (one GET), active (full scan)")
	outputDir := fs.String("output", "analysis_output/web_scan", "Directory to write the Markdown report")
	iOwnTarget := fs.Bool("i-own-this-target", false, "Safety gate: confirm you have permission to scan this target")

	// ── Import modes ──────────────────────────────────────────────────────────
	curlCmd := fs.String("curl", "", `Scan a specific request expressed as a curl command.\n  Example: --curl "curl 'https://example.com/api' -H 'Cookie: sess=abc' -X POST --data 'q=test'"`)
	rawRequest := fs.String("raw-request", "", "Path to a file containing a raw HTTP request (Burp Suite format)")
	rawScheme := fs.String("raw-scheme", "https", "Scheme to use when importing a raw HTTP request (http|https)")
	htmlBody := fs.String("html-body", "", "Path to an HTML file or downloaded webpage directory for passive analysis (supports browser-saved bundles and .js.загружено)")

	// ── Analysis options ──────────────────────────────────────────────────────
	jwtWordlist := fs.String("jwt-wordlist", "", "Path to a wordlist file for JWT secret brute-forcing")

	// ── Output flags ──────────────────────────────────────────────────────────
	exportCurl := fs.Bool("export-curl", false, "Print a curl command for each finding so it can be reproduced manually")
	jsonOutput := fs.Bool("json", false, "Print findings as JSON to stdout in addition to the Markdown report")

	if len(args) > 0 && args[0] == "-test-run-only" {
		return 0
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}

	// ── Input validation ──────────────────────────────────────────────────────
	modes := 0
	if *targetURL != "" {
		modes++
	}
	if *curlCmd != "" {
		modes++
	}
	if *rawRequest != "" {
		modes++
	}
	if *htmlBody != "" {
		modes++
	}

	if modes == 0 {
		fmt.Println("Usage:")
		fmt.Println("  go run cmd/vulnscan/main.go [--i-own-this-target] [MODE] [OPTIONS]")
		return 1
	}
	if modes > 1 {
		fmt.Println("[-] Only one scan mode can be used at a time (--target / --curl / --raw-request / --html-body)")
		return 1
	}

	// ── HTML body / directory passive mode ─────────────────────────────────────
	if *htmlBody != "" {
		info, err := os.Stat(*htmlBody)
		if err != nil {
			fmt.Printf("[-] Failed to access HTML body path: %v\n", err)
			return 1
		}

		scanner, _ := vulnscan.NewScanner("http://localhost")
		scanner.Config.IOwnThisTarget = true // passive only — no requests made

		var vulns []vulnscan.Vulnerability
		sourceURL := "file://" + *htmlBody

		if info.IsDir() {
			fmt.Printf("[*] Scanning downloaded webpage directory: %s\n", *htmlBody)
			vulns, err = scanner.ScanHTMLDirectory(*htmlBody)
			if err != nil {
				fmt.Printf("[-] Failed to scan directory: %v\n", err)
				return 1
			}
		} else {
			data, err := os.ReadFile(*htmlBody)
			if err != nil {
				fmt.Printf("[-] Failed to read HTML body file: %v\n", err)
				return 1
			}
			vulns = scanner.ScanFileContent(*htmlBody, string(data), sourceURL)
		}

		fmt.Printf("\n[+] Passive HTML/directory scan complete. %d finding(s).\n", len(vulns))
		printResults(vulns, *outputDir, sourceURL, *exportCurl, *jsonOutput, nil)
		return 0
	}

	// ── Curl command import mode ───────────────────────────────────────────────
	if *curlCmd != "" {
		if !*iOwnTarget {
			fmt.Println("[-] --i-own-this-target is required for active scanning. Only use this on systems you own or have explicit permission to test.")
			return 1
		}

		parsed, err := vulnscan.ParseCurlCommand(*curlCmd)
		if err != nil {
			fmt.Printf("[-] Failed to parse curl command: %v\n", err)
			return 1
		}

		req, err := parsed.ToHTTPRequest()
		if err != nil {
			fmt.Printf("[-] Failed to build HTTP request from curl: %v\n", err)
			return 1
		}

		scanner, err := vulnscan.NewScanner(req.URL.String())
		if err != nil {
			fmt.Printf("[-] Scanner init error: %v\n", err)
			return 1
		}
		scanner.Config.IOwnThisTarget = true
		scanner.Config.JWTWordlist = *jwtWordlist
		scanner.LogFunc = func(msg string) { fmt.Print(msg) }
		scanner.Client = parsed.BuildHTTPClient(scanner.Client)

		vulns, err := scanner.ScanFromRequest(req)
		if err != nil {
			fmt.Printf("[-] Scan error: %v\n", err)
			return 1
		}

		printResults(vulns, *outputDir, req.URL.String(), *exportCurl, *jsonOutput, req.Header)
		return 0
	}

	// ── Raw HTTP request import mode ───────────────────────────────────────────
	if *rawRequest != "" {
		if !*iOwnTarget {
			fmt.Println("[-] --i-own-this-target is required for active scanning.")
			return 1
		}

		data, err := os.ReadFile(*rawRequest)
		if err != nil {
			fmt.Printf("[-] Failed to read raw request file: %v\n", err)
			return 1
		}

		req, err := vulnscan.ParseRawHTTPRequest(string(data), *rawScheme)
		if err != nil {
			fmt.Printf("[-] Failed to parse raw HTTP request: %v\n", err)
			return 1
		}

		scanner, err := vulnscan.NewScanner(req.URL.String())
		if err != nil {
			fmt.Printf("[-] Scanner init error: %v\n", err)
			return 1
		}
		scanner.Config.IOwnThisTarget = true
		scanner.Config.JWTWordlist = *jwtWordlist
		scanner.LogFunc = func(msg string) { fmt.Print(msg) }

		vulns, err := scanner.ScanFromRequest(req)
		if err != nil {
			fmt.Printf("[-] Scan error: %v\n", err)
			return 1
		}

		printResults(vulns, *outputDir, req.URL.String(), *exportCurl, *jsonOutput, req.Header)
		return 0
	}

	// ── Standard URL scan mode ─────────────────────────────────────────────────
	mode, err := vulnscan.ParseScanMode(*webMode)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		return 1
	}
	if mode == vulnscan.ScanModeActive && !*iOwnTarget {
		fmt.Println("[-] --i-own-this-target is required for active scanning. Only use this on systems you own or have explicit permission to test.")
		return 1
	}

	scanner, err := vulnscan.NewScanner(*targetURL)
	if err != nil {
		fmt.Printf("[-] Initialization error: %v\n", err)
		return 1
	}
	scanner.Config.IOwnThisTarget = mode == vulnscan.ScanModeActive && *iOwnTarget
	scanner.Config.JWTWordlist = *jwtWordlist
	scanner.LogFunc = func(msg string) { fmt.Print(msg) }

	result, err := scanner.ScanWithMode(context.Background(), mode)
	if err != nil {
		fmt.Printf("[-] Scan execution error: %v\n", err)
		return 1
	}
	if result.Status != nil {
		state := "not healthy"
		if result.Status.OK {
			state = "HTTP 200"
		}
		fmt.Printf("[+] Website status: %s (%s, %s)\n", state, result.Status.Status, result.Status.Duration.Round(time.Millisecond))
	}

	printResults(result.Findings, *outputDir, *targetURL, *exportCurl, *jsonOutput, nil)
	return 0
}

// printResults displays findings in the terminal and writes the Markdown report.
func printResults(vulns []vulnscan.Vulnerability, outputDir, targetURL string, exportCurlFlag bool, jsonFlag bool, reqHeaders map[string][]string) {
	fmt.Printf("\n[+] Scan complete. Detected %d security finding(s).\n", len(vulns))

	reportPath := vulnscan.GenerateMarkdownReport(vulns, targetURL, outputDir)
	fmt.Printf("[+] Report saved to: %s\n", reportPath)

	if jsonFlag {
		printJSON(vulns)
	}

	fmt.Println("\n================ Scan Results Matrix ================")
	for i, v := range vulns {
		fmt.Printf(" [%d] %-8s | %-20s | %s\n", i+1, v.Severity, v.ID, v.Name)
		if v.Parameter != "" {
			fmt.Printf("     Parameter: %s", v.Parameter)
			if v.Payload != "" {
				fmt.Printf(" | Payload: %s", v.Payload)
			}
			fmt.Println()
		}
		if v.Evidence != "" {
			fmt.Printf("     Evidence: %s\n", v.Evidence)
		}
		if exportCurlFlag {
			// Build simple header map from net/http canonical format
			flatHeaders := make(map[string]string)
			for k, vals := range reqHeaders {
				if len(vals) > 0 {
					flatHeaders[k] = vals[0]
				}
			}
			fmt.Printf("     Reproduce:\n       %s\n", vulnscan.ExportVulnAsCurl(v, "GET", flatHeaders, ""))
		}
		fmt.Println()
	}
	fmt.Println("=====================================================")
}

// printJSON prints findings as newline-delimited JSON to stdout.
func printJSON(vulns []vulnscan.Vulnerability) {
	fmt.Println("\n--- JSON Output ---")
	var sb strings.Builder
	sb.WriteString("[\n")
	for i, v := range vulns {
		sb.WriteString(fmt.Sprintf(
			"  {\"id\":%q,\"name\":%q,\"severity\":%q,\"url\":%q,\"parameter\":%q,\"payload\":%q,\"evidence\":%q}",
			v.ID, v.Name, v.Severity, v.URL, v.Parameter, v.Payload, v.Evidence,
		))
		if i < len(vulns)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("]\n")
	fmt.Print(sb.String())
}
