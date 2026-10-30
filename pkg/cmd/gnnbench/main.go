// Command gnnbench measures the analyzer scan pipeline and the Go side of
// the GNN stage on a real APK, comparing the two input modes:
//
//	direct — the default scan path (in-memory DEX IR, no smali on disk)
//	decode — a --decode-style smali materialization, then scan of the dir
//
// Usage:
//
//	go run ./pkg/cmd/gnnbench -apk app.apk -mode direct
//	go run ./pkg/cmd/gnnbench -apk app.apk -mode decode
//
// The GNN phase reproduces the exact Go-side work of the classification
// stage (tensor build + single-pass digest + dedup) without the Rust FFI
// call, so it runs in environments where the native library is unavailable.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/gnngraph"
	"mega-analyzer/pkg/internal/pipeline"
	"mega-analyzer/pkg/ml/gnncache"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gnnbench:", err)
		os.Exit(1)
	}
}

func run() error {
	apk := flag.String("apk", "", "path to the APK to scan")
	mode := flag.String("mode", "direct", "direct (in-memory DEX) or decode (smali materialization)")
	flag.Parse()
	if *apk == "" {
		return fmt.Errorf("-apk is required")
	}

	ctx := context.Background()
	extractor := apkloader.NewExtractor()

	totalStart := time.Now()
	prepStart := time.Now()
	var dir string
	switch *mode {
	case "direct":
		d, err := extractor.PrepareInputWithOptions(ctx, *apk, apkloader.PrepareOptions{})
		if err != nil {
			return fmt.Errorf("prepare input: %w", err)
		}
		dir = d
	case "decode":
		out, err := os.MkdirTemp("", "gnnbench_decode_*")
		if err != nil {
			return err
		}
		d, derr := extractor.DecodeAPK(ctx, *apk, apkloader.DecodeOptions{OutputDir: out})
		if derr != nil {
			return fmt.Errorf("decode apk: %w", derr)
		}
		dir = d
	default:
		return fmt.Errorf("unknown mode %q (want direct or decode)", *mode)
	}
	defer os.RemoveAll(dir)
	prepElapsed := time.Since(prepStart)

	p, err := pipeline.NewPipeline(config.DefaultConfig())
	if err != nil {
		return fmt.Errorf("new pipeline: %w", err)
	}
	scanStart := time.Now()
	result, err := p.Run(ctx, dir)
	if err != nil {
		return fmt.Errorf("pipeline run: %w", err)
	}
	scanElapsed := time.Since(scanStart)

	// Collect CFGs with the same gate as the GNN stage (>= 3 nodes).
	cfgBuilder := cfg.NewCFGBuilder()
	var cfgs []*cfg.ControlFlowGraph
	for _, file := range result.Files {
		if file == nil {
			continue
		}
		if file.CFG != nil && len(file.CFG.Nodes) >= 3 {
			cfgs = append(cfgs, file.CFG)
		}
		if file.SmaliClass != nil {
			for i := range file.SmaliClass.Methods {
				g := gnngraph.BuildMethodCFG(cfgBuilder, file.SmaliClass.Name, &file.SmaliClass.Methods[i])
				if g != nil && len(g.Nodes) >= 3 {
					cfgs = append(cfgs, g)
				}
			}
		}
	}

	// Go side of the GNN stage: tensor build + digest + dedup, no FFI.
	workers := runtime.GOMAXPROCS(0)
	if workers > 32 {
		workers = 32
	}
	if workers < 1 {
		workers = 1
	}
	var msBefore, msAfter runtime.MemStats
	runtime.ReadMemStats(&msBefore)
	gnnStart := time.Now()

	jobs := make(chan *cfg.ControlFlowGraph, len(cfgs))
	for _, g := range cfgs {
		jobs <- g
	}
	close(jobs)

	var (
		mu          sync.Mutex
		unique      = make(map[[32]byte]struct{}, len(cfgs))
		totalNodes  int64
		totalEdges  int64
		builtGraphs int64
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			builder := &gnngraph.Builder{}
			localDigests := make([][32]byte, 0, 1024)
			var localNodes, localEdges, localBuilt int64
			for g := range jobs {
				graph := builder.Build(g)
				if graph == nil {
					continue
				}
				tensor := &gnncache.GraphTensor{
					RowPtrs:    graph.RowPtrs,
					ColIndices: graph.ColIndices,
					EdgeTypes:  graph.EdgeTypes,
					Features:   graph.Features,
					NumNodes:   graph.NumNodes,
					FeatureDim: graph.FeatureDim,
				}
				localDigests = append(localDigests, gnncache.TensorDigest(tensor))
				localNodes += int64(graph.NumNodes)
				localEdges += int64(len(graph.ColIndices))
				localBuilt++
			}
			mu.Lock()
			for _, d := range localDigests {
				unique[d] = struct{}{}
			}
			totalNodes += localNodes
			totalEdges += localEdges
			builtGraphs += localBuilt
			mu.Unlock()
		}()
	}
	wg.Wait()
	gnnElapsed := time.Since(gnnStart)
	runtime.ReadMemStats(&msAfter)
	totalElapsed := time.Since(totalStart)

	fmt.Printf("RESULT mode=%s\n", *mode)
	fmt.Printf("  prepare_input:   %v\n", prepElapsed.Round(time.Millisecond))
	fmt.Printf("  pipeline_scan:   %v\n", scanElapsed.Round(time.Millisecond))
	fmt.Printf("  gnn_go_stage:    %v  (%d workers)\n", gnnElapsed.Round(time.Millisecond), workers)
	fmt.Printf("  total:           %v\n", totalElapsed.Round(time.Millisecond))
	fmt.Printf("  files_analyzed:  %d\n", len(result.Files))
	fmt.Printf("  cfgs>=3nodes:    %d\n", len(cfgs))
	fmt.Printf("  graphs_built:    %d (unique %d, %.1f%% dedup)\n", builtGraphs, len(unique), dedupPct(builtGraphs, int64(len(unique))))
	fmt.Printf("  nodes/edges:     %d / %d\n", totalNodes, totalEdges)
	fmt.Printf("  gnn_allocs:      %.1f MB\n", float64(msAfter.TotalAlloc-msBefore.TotalAlloc)/(1024*1024))
	return nil
}

func dedupPct(total, unique int64) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(total-unique) / float64(total)
}
