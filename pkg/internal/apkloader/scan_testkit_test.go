package apkloader

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestScanTestKitCorpus(t *testing.T) {
	files, err := filepath.Glob("../../../testkit/native_test_corpus/bin/*.elf")
	if err != nil || len(files) == 0 {
		t.Skip("testkit corpus not present")
	}

	sort.Strings(files)
	fmt.Printf("\n=== SCANNING %d NATIVE ELF FILES FROM TESTKIT ===\n\n", len(files))

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("Failed to read %s: %v", file, err)
			continue
		}

		rep, ok := AnalyzeNativeGo(data)
		if !ok {
			t.Errorf("Not a recognized ELF binary: %s", file)
			continue
		}

		baseName := filepath.Base(file)
		fmt.Printf("───────────────────────────────────────────────────\n")
		fmt.Printf("📄 BINARY: %s (%d bytes)\n", baseName, len(data))
		fmt.Printf("   Arch: %s | Verdict: %s | Score: %d/100\n", rep.TargetArch, rep.Verdict, rep.Score)

		// Hardening
		h := rep.Hardening
		nxStr, pieStr, canaryStr, strippedStr := "no", "no", "no", "no"
		if h.NX != nil && *h.NX {
			nxStr = "yes"
		}
		if h.PIE != nil && *h.PIE {
			pieStr = "yes"
		}
		if h.StackCanary != nil && *h.StackCanary {
			canaryStr = "yes"
		}
		if h.Stripped != nil && *h.Stripped {
			strippedStr = "yes"
		}
		fmt.Printf("   Hardening: NX=%s, PIE=%s, Canary=%s, Relro=%s, Stripped=%s\n",
			nxStr, pieStr, canaryStr, h.Relro, strippedStr)

		// Findings
		if len(rep.Findings) == 0 {
			fmt.Printf("   Findings: 0 (CLEAN)\n")
		} else {
			fmt.Printf("   Findings: %d\n", len(rep.Findings))
			for i, f := range rep.Findings {
				fmt.Printf("     [%d] [%s] %s: %s\n", i+1, strings.ToUpper(f.Severity), f.Title, f.Description)
				if f.Evidence != "" {
					fmt.Printf("         Evidence: %s\n", f.Evidence)
				}
			}
		}

		// Crack points
		cps := DetectNativeCrackPoints(data, file)
		if len(cps) > 0 {
			fmt.Printf("   Native Crack Points: %d\n", len(cps))
			for _, cp := range cps {
				fmt.Printf("     • [%s] %s (%s, confidence=%.2f)\n",
					cp.Category, cp.Method, cp.Suggestion, cp.Confidence)
			}
		}
		fmt.Println()
	}
}
