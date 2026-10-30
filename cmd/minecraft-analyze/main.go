// Command minecraft-analyze inspects Minecraft Bedrock packages.
// It never executes package code and never extracts an archive to disk.
// Java mods (.jar) belong to the JAR analyzer, not here.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/minecraft"
)

func main() {
	path := flag.String("path", "", "ZIP/MCPACK/MCADDON or extracted Bedrock pack (Java .jar goes to the JAR analyzer)")
	jsonOut := flag.Bool("json", false, "write complete report as JSON")
	output := flag.String("output", "analysis_output/minecraft", "HTML and JSON report directory (ignored with -json)")
	maxEntries := flag.Int64("max-entries", 50000, "maximum archive entries")
	maxExpand := flag.Int64("max-expand-mb", 512, "maximum expanded content in MiB")
	maxInput := flag.Int64("max-input-mb", 256, "maximum input size in MiB")
	maxDepth := flag.Int("max-depth", 3, "maximum nested archive depth")
	maxEntry := flag.Int64("max-entry-mb", 32, "maximum inspected entry size in MiB")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "usage: minecraft-analyze -path <pack.mcpack|addon.mcaddon|directory>")
		os.Exit(2)
	}
	if strings.HasSuffix(strings.ToLower(*path), ".jar") {
		fmt.Fprintln(os.Stderr, "Java mods (.jar) are analyzed by the JAR analyzer, not minecraft-analyze")
		os.Exit(2)
	}
	if *maxEntries <= 0 || *maxDepth < 1 || *maxDepth > 16 || *maxExpand < 1 || *maxExpand > 4096 || *maxInput < 1 || *maxInput > 4096 || *maxEntry < 1 || *maxEntry > 4096 {
		fmt.Fprintln(os.Stderr, "limits must be positive; sizes <=4096 MiB and depth <=16")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r, e := minecraft.AnalyzePath(ctx, *path, minecraft.Options{MaxEntries: *maxEntries, MaxUncompressed: *maxExpand << 20, MaxInputBytes: *maxInput << 20, MaxEntryBytes: *maxEntry << 20, MaxDepth: *maxDepth})
	if e != nil {
		fmt.Fprintln(os.Stderr, "analysis failed:", e)
		os.Exit(1)
	}
	if *jsonOut {
		if e = r.JSON(os.Stdout); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if e = minecraft.WriteReports(*output, r); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Printf("Format: %s\nComplete: %t\nRisk: %d/100\nEntries: %d | expanded: %s | classes: %d | scripts: %d | textures: %d\n", r.Format, r.Complete, r.RiskScore, r.Stats.Entries, formatBytes(r.Stats.UncompressedBytes), r.Stats.Classes, r.Stats.Scripts, r.Stats.Textures)
	for _, p := range r.Packs {
		fmt.Printf("  %s %s %s %s\n", p.Format, p.Loader, p.ID, p.Version)
	}
	for _, f := range r.Findings {
		fmt.Printf("[%s] %s: %s\n", f.Severity, f.Title, f.Detail)
	}
	fmt.Println("Report:", filepath.Join(*output, "REPORT.html"))
}
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for n/div >= unit && exp < 5 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
