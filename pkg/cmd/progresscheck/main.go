// Smoke harness: runs the pipeline on demo/vulnerable-app, records every
// OnProgress callback and prints the step deltas + debug category logs.
package main

import (
	"context"
	"fmt"
	"os"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/pipeline"
	"mega-analyzer/pkg/logger"
)

func main() {
	logger.Get().SetLevel(logger.DebugLevel)

	cfg := config.DefaultConfig()

	p, err := pipeline.NewPipeline(cfg)
	if err != nil {
		fmt.Println("pipeline error:", err)
		os.Exit(1)
	}

	type tick struct{ cur, total int }
	var ticks []tick
	p.OnProgress = func(stage string, current, total int) {
		if stage == "scan_and_analyze" && total > 0 {
			ticks = append(ticks, tick{current, total})
		}
	}

	target := "demo/vulnerable-app"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	res, err := p.Run(context.Background(), target)
	if err != nil {
		fmt.Println("run error:", err)
		os.Exit(1)
	}

	fmt.Println("\n=== PROGRESS TICKS ===")
	prev := 0
	maxDelta := 0
	for i, t := range ticks {
		d := t.cur - prev
		if d > maxDelta && i > 0 {
			maxDelta = d
		}
		fmt.Printf("tick %2d: %d/%d (delta %d)\n", i, t.cur, t.total, d)
		prev = t.cur
	}
	fmt.Println("max delta between updates:", maxDelta)
	fmt.Println("total matches:", res.Stats.TotalMatches, "files:", res.Stats.TotalFiles)
}
