package main

import (
	"flag"
	"fmt"
	"os"

	"mega-analyzer/pkg/ml"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("pattern-analysis", flag.ContinueOnError)
	outputPath := fs.String("output", "analysis_output/pattern_effectiveness_report.txt", "Output path for the report")
	listOnly := fs.Bool("list", false, "List all patterns without analysis")
	compareOnly := fs.Bool("compare", false, "Compare pattern tiers")
	patternID := fs.String("pattern", "", "Analyze specific pattern by ID")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}

	// List patterns only
	if *listOnly {
		ml.ListAllPatterns()
		return 0
	}

	// Compare tiers only
	if *compareOnly {
		ml.ComparePatternTiers()
		return 0
	}

	// Analyze specific pattern
	if *patternID != "" {
		effectiveness, err := ml.AnalyzePatternByID(*patternID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

		fmt.Printf("Pattern: %s\n", effectiveness.PatternID)
		fmt.Printf("Tier: %s\n", effectiveness.Tier)
		fmt.Printf("Success Rate: %.1f%%\n", effectiveness.TruePositiveRate*100)
		fmt.Printf("False Positive Rate: %.1f%%\n", effectiveness.FalsePositiveRate*100)
		fmt.Printf("Crash Rate: %.1f%%\n", effectiveness.CrashRate*100)
		fmt.Printf("Confidence: %.2f\n", effectiveness.Confidence)
		fmt.Printf("Reason: %s\n", effectiveness.TierReason)
		return 0
	}

	// Run full analysis
	if err := ml.RunEffectivenessAnalysis(*outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
