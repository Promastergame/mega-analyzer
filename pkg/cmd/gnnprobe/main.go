//go:build cgo && omnisec_ml_gnn

// Command gnnprobe runs ONLY the GNN classification stage over a smali tree:
// parse smali -> per-method CFG -> CSR graph -> Rust GNN inference.
// No pattern pipeline, no reports — the minimal serving path.
//
// Dataset mode (for fine-tuning):
//
//	gnnprobe <smali_dir> <weights.json> --dataset-out out.jsonl \
//	        [--max-graphs N] [--benign-confirmed] [--label N]
//
// Emits jsonl records in the exact pkg/ml/gnndataset format consumed by
// gnn-train (dex_synth::load_jsonl_grouped): nested features, label,
// label_confirmed, apk_path (the smali dir — also the by-APK split group)
// and graph_hash (dedup key).
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/gnngraph"
	"mega-analyzer/pkg/internal/parser"
	gnn "mega-analyzer/pkg/ml/gnn"
)

type hit struct {
	class, method, label string
	conf                 float32
}

type dsRecord struct {
	NumNodes       uint64      `json:"num_nodes"`
	FeatureDim     uint64      `json:"feature_dim"`
	RowPtrs        []uint64    `json:"row_ptr"`
	ColIndices     []uint64    `json:"col_idx"`
	EdgeTypes      []uint32    `json:"edge_types"`
	Features       [][]float32 `json:"features"`
	Label          int         `json:"label"`
	LabelName      string      `json:"label_name"`
	LabelConfirmed bool        `json:"label_confirmed"`
	Confidence     float32     `json:"confidence"`
	ClassProbs     []float32   `json:"class_probs,omitempty"`
	APKPath        string      `json:"apk_path,omitempty"`
	GraphHash      string      `json:"graph_hash"`
	FeatureSchema  string      `json:"feature_schema,omitempty"`
	MethodName     string      `json:"method_name,omitempty"`
	FilePath       string      `json:"file_path,omitempty"`
	ScannedAt      string      `json:"scanned_at"`
	Notes          string      `json:"notes,omitempty"`
}

const (
	datasetNodeCap = 4096 // skip exporting graphs above this (tensor budget)
)

func main() {
	var (
		root, weights   string
		datasetOut      string
		maxGraphs       int
		benignConfirmed bool
		forcedLabel     = -1
	)
	args := os.Args[1:]
	var pos []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dataset-out":
			i++
			datasetOut = args[i]
		case "--max-graphs":
			i++
			maxGraphs, _ = strconv.Atoi(args[i])
		case "--benign-confirmed":
			benignConfirmed = true
		case "--label":
			i++
			forcedLabel, _ = strconv.Atoi(args[i])
		default:
			pos = append(pos, args[i])
		}
	}
	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gnnprobe <smali_dir> <gnn_weights.json> [--dataset-out f] [--max-graphs N] [--benign-confirmed] [--label N]")
		os.Exit(2)
	}
	root, weights = pos[0], pos[1]
	noInfer := os.Getenv("NOINFER") != ""
	if noInfer {
		fmt.Fprintln(os.Stderr, "NOINFER mode: skipping model inference")
	}

	started := time.Now()
	var model *gnn.Model
	if !noInfer {
		var err error
		model, err = gnn.LoadModel(weights)
		if err != nil {
			fmt.Fprintln(os.Stderr, "model load:", err)
			os.Exit(1)
		}
		defer model.Close()
	}
	fmt.Fprintf(os.Stderr, "model loaded in %s\n", time.Since(started).Round(time.Millisecond))

	var files []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".smali") {
			files = append(files, path)
		}
		return nil
	})
	fmt.Fprintf(os.Stderr, "smali files: %d\n", len(files))

	var (
		parsedClasses atomic.Int64
		parseFailures atomic.Int64
		totalMethods  atomic.Int64
		cfgless       atomic.Int64
		chainFallback atomic.Int64
		oversized     atomic.Int64
		classified    atomic.Int64
		benign        atomic.Int64
		hitsMu        sync.Mutex
		hits          []hit
		classCounts   = map[string]*atomic.Int64{}
		dsRecords     []*dsRecord // guarded by hitsMu
	)

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	var inferMu sync.Mutex
	builders := sync.Pool{New: func() interface{} { b := cfg.NewCFGBuilder(); return b }}
	jobs := make(chan string, 256)
	var wg sync.WaitGroup

	record := func(label string) {
		hitsMu.Lock()
		defer hitsMu.Unlock()
		c, ok := classCounts[label]
		if !ok {
			c = &atomic.Int64{}
			classCounts[label] = c
		}
		c.Add(1)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				data, err := os.ReadFile(path)
				if err != nil {
					parseFailures.Add(1)
					continue
				}
				class, err := parser.NewSmaliParser(string(data)).Parse()
				if err != nil || class == nil {
					parseFailures.Add(1)
					continue
				}
				parsedClasses.Add(1)
				// Mirror pipeline processSmali: bodies are file line slices
				// by 1-based LineStart..LineEnd, not set by the parser itself.
				lines := strings.Split(string(data), "\n")
				builder, _ := builders.Get().(*cfg.CFGBuilder)
				for i := range class.Methods {
					m := &class.Methods[i]
					if m.LineStart > 0 && m.LineEnd <= len(lines) {
						m.Body = lines[m.LineStart-1 : m.LineEnd]
					}
					if len(m.Body) < 3 {
						continue
					}
					totalMethods.Add(1)
					methodCFG := gnngraph.BuildMethodCFG(builder, class.Name, m)
					isChainFallback := false
					if methodCFG == nil || len(methodCFG.Nodes) < 3 {
						chainCFG := gnngraph.BuildChainCFG(class.Name, m)
						if chainCFG == nil {
							cfgless.Add(1)
							continue
						}
						methodCFG = chainCFG
						isChainFallback = true
						chainFallback.Add(1)
					}
					graph := gnngraph.Build(methodCFG)
					if graph == nil || graph.NumNodes == 0 || graph.NumNodes > 8192 {
						oversized.Add(1)
						continue
					}
					var pred *gnn.Prediction
					if noInfer {
						pred = &gnn.Prediction{PredictedClass: 0, Confidence: 1}
					} else {
						inferMu.Lock()
						var err error
						pred, err = model.Infer(graph)
						inferMu.Unlock()
						if err != nil {
							oversized.Add(1)
							continue
						}
					}
					classified.Add(1)
					idx := int(pred.PredictedClass)
					if idx == 0 {
						benign.Add(1)
					} else {
						record(gnn.VulnClassName(gnn.VulnClass(idx)))
					}

					// Dataset export: collect the raw tensor + prediction.
					if datasetOut != "" && graph.NumNodes <= datasetNodeCap {
						feats := make([][]float32, graph.NumNodes)
						for n := uint64(0); n < graph.NumNodes; n++ {
							feats[n] = graph.Features[n*graph.FeatureDim : (n+1)*graph.FeatureDim : (n+1)*graph.FeatureDim]
						}
						h := sha256.New()
						var b8 [8]byte
						for _, v := range graph.RowPtrs {
							binary.Write(h, binary.LittleEndian, v)
						}
						for _, v := range graph.ColIndices {
							binary.Write(h, binary.LittleEndian, v)
						}
						for _, f := range graph.Features {
							binary.Write(h, binary.LittleEndian, f)
						}
						_ = b8
						label := idx
						confirmed := false
						notes := "model-prediction"
						if benignConfirmed {
							label = 0
							confirmed = true
							notes = "analyst-confirmed-clean-game;model-said=" +
								gnn.VulnClassName(gnn.VulnClass(idx))
						}
						if forcedLabel >= 0 {
							label = forcedLabel
							confirmed = true
							notes = "forced-label"
						}
						if isChainFallback {
							if notes == "model-prediction" {
								notes = "chain-fallback"
							} else {
								notes += ";chain-fallback"
							}
						}
						rec := &dsRecord{
							NumNodes:       graph.NumNodes,
							FeatureDim:     graph.FeatureDim,
							RowPtrs:        graph.RowPtrs,
							ColIndices:     graph.ColIndices,
							EdgeTypes:      graph.EdgeTypes,
							Features:       feats,
							Label:          label,
							LabelName:      gnn.VulnClassName(gnn.VulnClass(label)),
							LabelConfirmed: confirmed,
							Confidence:     pred.Confidence,
							ClassProbs:     pred.ClassProbs,
							APKPath:        root,
							GraphHash:      hex.EncodeToString(h.Sum(nil)),
							FeatureSchema:  gnngraph.FeatureSchemaID,
							MethodName:     class.Name + "->" + m.Name,
							FilePath:       path,
							ScannedAt:      time.Now().UTC().Format(time.RFC3339),
							Notes:          notes,
						}
						hitsMu.Lock()
						dsRecords = append(dsRecords, rec)
						hitsMu.Unlock()
					}

					if idx == 0 {
						continue
					}
					label := gnn.VulnClassName(gnn.VulnClass(idx))
					hitsMu.Lock()
					hits = append(hits, hit{
						class:  class.Name,
						method: m.Name,
						label:  label,
						conf:   pred.Confidence,
					})
					hitsMu.Unlock()
				}
			}
		}()
	}
	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	wg.Wait()

	if datasetOut != "" {
		exportDataset(datasetOut, dsRecords, maxGraphs)
	}

	fmt.Printf("elapsed            : %s\n", time.Since(started).Round(time.Millisecond))
	fmt.Printf("classes parsed     : %d (parse failures: %d)\n", parsedClasses.Load(), parseFailures.Load())
	fmt.Printf("methods with body  : %d\n", totalMethods.Load())
	fmt.Printf("cfg-less skipped   : %d\n", cfgless.Load())
	fmt.Printf("chain-fallback     : %d\n", chainFallback.Load())
	fmt.Printf("oversized/failed   : %d\n", oversized.Load())
	fmt.Printf("classified         : %d\n", classified.Load())
	fmt.Printf("benign             : %d\n", benign.Load())
	fmt.Println("---- argmax class distribution ----")
	names := make([]string, 0, len(classCounts))
	for k := range classCounts {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Printf("  %-18s %d\n", k, classCounts[k].Load())
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].conf > hits[j].conf })
	fmt.Printf("---- top non-benign (of %d) ----\n", len(hits))
	for i, h := range hits {
		if i == 30 {
			break
		}
		fmt.Printf("  %.2f  %-16s %s -> %s\n", h.conf, h.label, short(h.class), h.method)
	}
}

// exportDataset samples up to maxGraphs records: half hard negatives
// (highest-confidence non-benign predictions), half everything else,
// then writes them as jsonl for gnn-train.
func exportDataset(path string, records []*dsRecord, maxGraphs int) {
	var out []*dsRecord
	if maxGraphs > 0 && len(records) > maxGraphs {
		var nonBenign, benignRecs []*dsRecord
		for _, r := range records {
			if r.Label != 0 {
				nonBenign = append(nonBenign, r)
			} else {
				benignRecs = append(benignRecs, r)
			}
		}
		sort.Slice(nonBenign, func(i, j int) bool { return nonBenign[i].Confidence > nonBenign[j].Confidence })
		half := maxGraphs / 2
		if len(nonBenign) > half {
			nonBenign = nonBenign[:half]
		}
		rng := rand.New(rand.NewSource(1337))
		rng.Shuffle(len(benignRecs), func(i, j int) { benignRecs[i], benignRecs[j] = benignRecs[j], benignRecs[i] })
		rest := maxGraphs - len(nonBenign)
		if len(benignRecs) > rest {
			benignRecs = benignRecs[:rest]
		}
		out = append(nonBenign, benignRecs...)
	} else {
		out = records
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dataset write failed: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range out {
		_ = enc.Encode(r)
	}
	fmt.Printf("dataset exported   : %d record(s) -> %s\n", len(out), path)
}

func short(class string) string {
	s := strings.TrimPrefix(class, "L")
	s = strings.TrimSuffix(s, ";")
	if len(s) > 70 {
		s = "…" + s[len(s)-70:]
	}
	return s
}
