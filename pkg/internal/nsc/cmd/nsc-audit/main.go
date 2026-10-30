// Command nsc-audit audits an Android Network Security Configuration
// (network_security_config.xml) and prints a markdown or JSON report.
//
// Usage:
//
//	nsc-audit [flags] <path-to-nsc.xml | extracted-apk-dir>
//
// Flags:
//
//	-json    output JSON instead of markdown
//	-target  label for the report (defaults to the path)
//	-strict  exit with code 2 when the verdict is "weak" or "dangerous"
package main

import (
	"flag"
	"fmt"
	"os"

	nsc "mega-analyzer/pkg/internal/nsc"
)

func main() {
	var (
		jsonOut = flag.Bool("json", false, "output JSON instead of markdown")
		target  = flag.String("target", "", "target label for the report (defaults to path)")
		strict  = flag.Bool("strict", false, "exit non-zero when verdict is weak or dangerous")
	)
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: nsc-audit [-json] [-strict] [-target label] <nsc.xml | extracted-apk-dir>")
		os.Exit(64)
	}
	path := flag.Arg(0)
	label := *target
	if label == "" {
		label = path
	}

	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsc-audit: %v\n", err)
		os.Exit(66)
	}

	var report *nsc.Report
	if info.IsDir() {
		report, err = nsc.AuditDir(path)
	} else {
		report, err = nsc.AuditFile(label, path)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsc-audit: %v\n", err)
		os.Exit(65)
	}

	if *jsonOut {
		b, err := nsc.RenderJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nsc-audit: %v\n", err)
			os.Exit(70)
		}
		fmt.Println(string(b))
	} else {
		fmt.Print(nsc.RenderMarkdown(report))
	}

	if *strict && (report.Verdict == "weak" || report.Verdict == "dangerous") {
		os.Exit(2)
	}
}
