package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/minecraft"
)

func runMinecraft(opts *CLIOptions) error {
	if opts.Target == "" {
		return fmt.Errorf("-minecraft requires -t <pack.zip|pack.mcpack|addon.mcaddon|directory> (Bedrock packs; Java mods go to the JAR analyzer)")
	}
	if strings.HasSuffix(strings.ToLower(opts.Target), ".jar") {
		return fmt.Errorf("Java mods (.jar) are analyzed by the JAR analyzer, not -minecraft: run analyzer -t %s instead", opts.Target)
	}
	if opts.Timeout < 0 || opts.MaxFiles < 0 {
		return fmt.Errorf("timeout and max-files must be non-negative")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 120
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	r, err := minecraft.AnalyzePath(ctx, opts.Target, minecraft.Options{MaxEntries: int64(opts.MaxFiles)})
	if err != nil {
		return err
	}
	if opts.JSON {
		return r.JSON(os.Stdout)
	}
	if err := minecraft.WriteReports(opts.Output, r); err != nil {
		return err
	}
	fmt.Printf("Minecraft: %s | complete=%t | %d files | %d packs | indicator score=%d/100\n", r.Format, r.Complete, len(r.Files), len(r.Packs), r.RiskScore)
	fmt.Printf("Classes: %d | scripts: %d | textures: %d | nested archives: %d | skipped: %d\n", r.Stats.Classes, r.Stats.Scripts, r.Stats.Textures, r.Stats.NestedArchives, r.Stats.Skipped)
	for _, f := range r.Findings {
		fmt.Printf("[%s] %s: %s\n", f.Severity, f.Title, f.Detail)
	}
	fmt.Printf("Report: %s\nJSON: %s\n", filepath.Join(opts.Output, "REPORT.html"), filepath.Join(opts.Output, "analysis.json"))
	return nil
}
