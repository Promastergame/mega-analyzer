//go:build cgo && omnisec_ml_gnn

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/contentcache"
	"mega-analyzer/pkg/internal/gnngraph"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml/gnn"
	"mega-analyzer/pkg/ml/gnncache"
	"mega-analyzer/pkg/ml/gnndataset"
)

// maxGNNWorkers caps concurrent graph preparation and inference work. Each
// worker allocates several node × hidden-dimension buffers in Go and Rust, so a
// CPU-wide default can turn one pathological method into multi-gigabyte RSS.
const maxGNNWorkers = 4

// gnnMinGraphNodes skips degenerate graphs: functions with fewer than three
// CFG nodes carry no exploitable structure for message passing and only
// waste FFI round-trips and cache space.
const gnnMinGraphNodes = 3

// gnnMethodEntry is one method scheduled for GNN classification.
//
// The unit of work is a method, not a file. A control-flow graph describes one
// method, but types.FileAnalysis.CFG — the field this stage used to read — is
// never assigned by anything in the tree, so the entry list came out empty and
// the stage classified nothing on every scan since it was written. Graphs are
// built per method from the parsed class body instead, the same way the
// benchmark harness and the crack-point finder already do it.
type gnnMethodEntry struct {
	path        string
	file        *types.FileAnalysis
	method      *types.SmaliMethod
	methodIndex int
}

// gnnLoadError marks a model load failure so it can be told apart from a
// per-graph inference failure after memoization.
type gnnLoadError struct{ err error }

func (e gnnLoadError) Error() string { return e.err.Error() }
func (e gnnLoadError) Unwrap() error { return e.err }

// runGNNClassification runs the GNN-based vulnerability classification
// pipeline over all control-flow graphs in the analysis result.
//
// Three layers keep it fast:
//  1. a run-local memo deduplicates identical graphs (multi-dex targets
//     often contain many copies of the same method), so each unique graph
//     is classified once per run, dummy weights included;
//  2. a persistent cache keyed by graph tensor + model weight fingerprint
//     skips inference entirely across runs (real weight files only);
//  3. remaining graphs are classified by a bounded worker pool sharing one
//     lazily loaded immutable model, so a fully cached run performs no FFI
//     calls and an uncached run parses the weight JSON only once.
func (a *App) runGNNClassification(ctx context.Context, result *types.AnalysisResult, modelPath string) error {
	if modelPath == "" {
		modelPath = gnncache.DummyModelPath
	}
	// Dummy weights are random: every downstream consumer (findings, verdict
	// reasoning, patch planning) must treat their output as absent evidence.
	dummyModel := modelPath == gnncache.DummyModelPath

	// Open the dataset writer so newly inferred unique graphs are persisted
	// for future re-training (memo duplicates and persistent-cache hits are
	// skipped — they were already recorded). Errors here are non-fatal: a
	// broken writer must not abort an otherwise healthy scan.
	var dsWriter *gnndataset.Writer
	if dsDir := gnndataset.DefaultWriterDir(); dsDir != "" {
		if dw, derr := gnndataset.Open(dsDir); derr == nil {
			dsWriter = dw
			defer dw.Close()
		} else {
			a.output.Warning("GNN dataset writer disabled: %v", derr)
		}
	}

	// Set up the persistent prediction cache. Dummy models are
	// Xavier-initialized with random weights on every load, so their outputs
	// are not reproducible and caching them would be wrong.
	var cache *gnncache.Cache
	var modelFingerprint string
	if a.opts.EnableContentCache {
		fingerprint, err := gnncache.ModelFingerprint(modelPath)
		switch {
		case err != nil:
			a.output.Warning("GNN cache disabled: cannot fingerprint model weights: %v", err)
		case fingerprint == "":
			a.output.Warning("GNN cache disabled: dummy model weights are re-randomized on every run")
		default:
			modelFingerprint = fingerprint
			cacheDir := a.opts.ContentCacheDir
			if cacheDir == "" || cacheDir == defaultContentCacheDir {
				// Keep the GNN cache next to the rest of the per-user
				// analyzer databases (~/.analyzer) instead of the working
				// directory, unless -content-cache-dir was set explicitly.
				if d := gnncache.DefaultCacheDir(); d != "" {
					cacheDir = d
				}
			}
			c, cerr := gnncache.Open(cacheDir, gnnCacheDiskLimitBytes(a.opts.ContentCacheMaxDiskMB), fingerprint)
			if cerr != nil {
				a.output.Warning("GNN cache disabled: %v", cerr)
			} else {
				cache = c
			}
		}
	}

	// Collect and order methods deterministically so findings and logs are
	// stable between runs (map iteration order is random).
	entries := make([]gnnMethodEntry, 0, len(result.Files))
	for path, file := range result.Files {
		if file == nil || file.SmaliClass == nil {
			continue
		}
		for i := range file.SmaliClass.Methods {
			m := &file.SmaliClass.Methods[i]
			if len(m.Body) < gnnMinGraphNodes {
				continue
			}
			entries = append(entries, gnnMethodEntry{
				path: path, file: file, method: m, methodIndex: i,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].path != entries[j].path {
			return entries[i].path < entries[j].path
		}
		return entries[i].method.Name < entries[j].method.Name
	})
	if len(entries) == 0 {
		return nil
	}
	// Feed the heaviest methods first (stable, so equal sizes keep the
	// deterministic order). Output order is fixed by the final findings sort,
	// so scheduling order is free to change; starting with the largest bodies
	// avoids a long single-worker tail at the end of the stage. Body length is
	// the proxy for graph size here — the graph itself is not built until a
	// worker picks the method up.
	sort.SliceStable(entries, func(i, j int) bool {
		return len(entries[i].method.Body) > len(entries[j].method.Body)
	})

	workers := a.opts.Workers
	if workers < 1 {
		// Default to all available cores instead of a single worker.
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > maxGNNWorkers {
		workers = maxGNNWorkers
	}
	if workers > len(entries) {
		workers = len(entries)
	}

	// Нативная часть (Rust/rayon) до этого игнорировала -workers: rayon по
	// умолчанию поднимает пул на ВСЕ ядра, поэтому при -workers=2 реально
	// молотило NumCPU потоков — отсюда лишние переключения контекста и RSS.
	// Пул создаётся лениво при первом вызове в нативный код, поэтому
	// переменную обязательно выставляем ДО gnn.LoadModel/инференса.
	if err := os.Setenv("RAYON_NUM_THREADS", strconv.Itoa(workers)); err != nil {
		a.output.Info("GNN: could not limit the rayon pool (%v), using the default", err)
	}

	a.output.Info("Running GNN over %d method(s) with %d worker(s) (weights: %s)...", len(entries), workers, modelPath)
	if dummyModel {
		a.output.Warning("GNN: DUMMY weights in use — outputs are random and MUST NOT be treated as vulnerability evidence; every finding below is flagged dummy and excluded from automatic verdicts")
	}

	workCtx, stopWork := context.WithCancel(ctx)
	defer stopWork()

	memo := gnncache.NewMemo()
	var (
		mu               sync.Mutex
		findings         []types.GNNFinding
		firstLoadErr     error
		inferFails       atomic.Int64
		cacheHits        atomic.Int64
		cacheStores      atomic.Int64
		cacheFailures    atomic.Int64
		datasetFailures  atomic.Int64
		datasetFull      atomic.Bool
		accepted         atomic.Int64
		uncertain        atomic.Int64
		libSuppressed    atomic.Int64
		otherClass       atomic.Int64
		bodylessSkipped  atomic.Int64
		oversizedSkipped atomic.Int64
		cfglessSkipped   atomic.Int64
		chainFallback    atomic.Int64
		chainAccepted    atomic.Int64
	)
	var (
		modelOnce sync.Once
		model     *gnn.Model
		modelErr  error
	)
	loadModel := func() (*gnn.Model, error) {
		modelOnce.Do(func() {
			if !dummyModel {
				// Reject incompatible weight files before the native runtime
				// sees them: feature schema, taxonomy, architecture shapes.
				// A file that fails here would otherwise load fine and emit
				// confident nonsense from mismatched features.
				meta, verr := gnn.ValidateModelFile(modelPath)
				if verr != nil {
					modelErr = verr
					return
				}
				if meta.TrainSamples > 0 {
					cal := "no calibration metadata"
					if meta.HasCalibration {
						cal = fmt.Sprintf("calibrated (q90=%.3f)", meta.ConformalQ90)
					}
					a.output.Info("GNN model: %s, trained on %d sample(s), val_acc=%.3f, schema v%d, %s",
						meta.TrainerVersion, meta.TrainSamples, meta.ValAccuracy, meta.FeatureSchemaVersion, cal)
				}
			}
			model, modelErr = gnn.LoadModel(modelPath)
			if modelErr == nil && cache != nil {
				// The cache key was derived before workers started. Verify that the
				// file loaded by the native runtime still has that fingerprint;
				// otherwise a concurrent model replacement could store predictions
				// under the wrong model key.
				currentFingerprint, fingerprintErr := gnncache.ModelFingerprint(modelPath)
				if fingerprintErr != nil || currentFingerprint != modelFingerprint {
					model.Close()
					model = nil
					if fingerprintErr != nil {
						modelErr = fmt.Errorf("verify loaded GNN model fingerprint: %w", fingerprintErr)
					} else {
						modelErr = errors.New("GNN model weights changed while classification was starting")
					}
				}
			}
		})
		return model, modelErr
	}

	// Keep only a small multiple of active workers queued. The complete entry
	// list already exists for deterministic ordering; buffering it again provides
	// no throughput benefit and extends the lifetime of parsed method objects.
	jobs := make(chan gnnMethodEntry, workers*2)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One builder per worker: the node-index map and successor
			// scratch are reused across every graph this worker converts.
			builder := &gnngraph.Builder{}
			cfgBuilder := cfg.NewCFGBuilder()
			for e := range jobs {
				if workCtx.Err() != nil {
					return
				}
				if len(e.method.Body) > gnnMaxMethodInstructions {
					oversizedSkipped.Add(1)
					continue
				}
				var methodCFG *cfg.ControlFlowGraph
				if e.methodIndex < len(e.file.MethodCFGs) {
					methodCFG = e.file.MethodCFGs[e.methodIndex]
				}
				if methodCFG == nil {
					// The scan-stage CFG cache can be present but sparsely filled:
					// MethodCFGs is sized for the whole class while individual slots
					// stay nil for methods the earlier stage skipped. The previous
					// `else` only rebuilt when the index ran past the end, so every
					// nil hole dropped its method from GNN coverage without a word.
					// Rebuilding locally is exactly what the bodyless branch below
					// already assumes has happened.
					methodCFG = gnngraph.BuildMethodCFG(cfgBuilder, e.file.SmaliClass.Name, e.method)
				}
				isChainFallback := false
				if methodCFG == nil || len(methodCFG.Nodes) < gnnMinGraphNodes {
					// Straight-line methods collapse to 1-2 CFG blocks (the
					// dominant cfg-less cause: ~70% of methods in game APKs).
					// Retry as a linear instruction chain so methods with
					// calls stay visible to the classifier; bodies with
					// fewer than 3 instructions still drop out here.
					if chainCFG := gnngraph.BuildChainCFG(e.file.SmaliClass.Name, e.method); chainCFG != nil {
						methodCFG = chainCFG
						isChainFallback = true
						chainFallback.Add(1)
					} else {
						// Previously an unobservable `continue`: a run could classify
						// nothing at all and give no reason for it.
						cfglessSkipped.Add(1)
						continue
					}
				}
				graph := builder.Build(methodCFG)
				if !gnnGraphWithinBudget(graph) {
					oversizedSkipped.Add(1)
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
				// Hash the tensor exactly once: both the run-local memo key
				// and the persistent cache key are derived from this digest, so
				// even the largest CSR + feature tensors get a single SHA-256
				// pass per run instead of one pass per key.
				digest := gnncache.TensorDigest(tensor)
				// Bind the method body to both keys. The tensor only describes
				// CFG shape and normalized features, so two unrelated methods
				// with the same silhouette would otherwise share a prediction.
				graphCtx := gnncache.ContextFromBody(digest, e.method.Body)
				graphKey := gnncache.GraphKeyFromContext(graphCtx)
				// Without a body the key stays collision-prone, so such graphs
				// are deduplicated within this run only and never persisted.
				usePersistent := cache != nil && graphCtx.HasBody
				if cache != nil && !graphCtx.HasBody {
					bodylessSkipped.Add(1)
				}
				var cacheKey contentcache.ContentKey
				if usePersistent {
					cacheKey = cache.KeyFromContext(graphCtx)
				}
				pred, err := memo.DoContext(workCtx, graphKey, func() (*gnncache.Prediction, error) {
					if usePersistent {
						if cached, ok := cache.Get(cacheKey); ok {
							cacheHits.Add(1)
							return cached, nil
						}
					}
					sharedModel, lerr := loadModel()
					if lerr != nil {
						return nil, gnnLoadError{err: lerr}
					}
					p, ierr := sharedModel.Infer(graph)
					if ierr != nil {
						return nil, ierr
					}
					out := &gnncache.Prediction{
						PredictedClass: int(p.PredictedClass),
						Confidence:     p.Confidence,
						ClassProbs:     p.ClassProbs,
					}
					if usePersistent {
						// Best effort: a failed cache write must not fail the scan.
						if cache.Put(cacheKey, out) == nil {
							cacheStores.Add(1)
						} else {
							cacheFailures.Add(1)
						}
					}
					// Persist graph + prediction to the training dataset. This
					// deliberately runs inside the memo miss path: each unique
					// graph is serialized at most once per run, and predictions
					// served from the persistent cache (already recorded by the
					// run that computed them) are skipped entirely. The previous
					// post-memo location re-marshaled the full tensor for every
					// duplicate method and even for fully cached scans.
					if dsWriter != nil && !datasetFull.Load() {
						ex := &gnndataset.Example{
							GraphHash:      hex.EncodeToString(graphKey[:16]),
							APKPath:        result.TargetDir,
							MethodName:     methodCFG.FullName,
							FilePath:       e.file.RelPath,
							FeatureSchema:  gnngraph.FeatureSchemaID,
							NumNodes:       tensor.NumNodes,
							FeatureDim:     tensor.FeatureDim,
							RowPtrs:        tensor.RowPtrs,
							ColIndices:     tensor.ColIndices,
							EdgeTypes:      tensor.EdgeTypes,
							Features:       gnndataset.FlattenFeatures(tensor.Features, tensor.NumNodes, tensor.FeatureDim),
							PredictedLabel: out.PredictedClass,
							LabelName:      gnn.VulnClassName(gnn.VulnClass(out.PredictedClass)),
							Confidence:     out.Confidence,
							ClassProbs:     out.ClassProbs,
							LabelConfirmed: false,
						}
						if isChainFallback {
							// Chain graphs are per-instruction one-hot
							// histograms, not per-block averages: flag them
							// so training never mixes the two silently.
							ex.Notes = "chain-fallback"
						}
						// Best effort — dataset write errors must not fail the scan.
						if derr := dsWriter.Append(ex); derr != nil {
							if errors.Is(derr, gnndataset.ErrDatasetFull) {
								datasetFull.Store(true)
							} else {
								datasetFailures.Add(1)
							}
						}
					}
					return out, nil
				})
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return
					}
					var le gnnLoadError
					if errors.As(err, &le) {
						mu.Lock()
						if firstLoadErr == nil {
							firstLoadErr = le.err
						}
						mu.Unlock()
						// Fatal for every remaining miss. Cancel the internal pool so the
						// feeder cannot block forever after all workers return.
						stopWork()
						return
					}
					inferFails.Add(1)
					continue
				}

				margin, valid := gnnPredictionMargin(pred)
				if !valid {
					inferFails.Add(1)
					continue
				}
				vulnName := gnn.VulnClassName(gnn.VulnClass(pred.PredictedClass))
				if vulnName == "benign" {
					otherClass.Add(1)
					continue
				}
				if vulnName == "unknown" || pred.Confidence < gnnMinConfidenceForClass(vulnName) || margin < gnnMinMargin ||
					gnnNormalizedEntropy(pred.ClassProbs) > gnnMaxNormalizedEntropy {
					uncertain.Add(1)
					continue
				}
				// Billing-library internals structurally are license
				// verification but never actionable: drop them as library
				// noise rather than findings (counted separately so the
				// quality-gate line stays about model uncertainty).
				if gnnLibrarySuppressed(methodCFG.FullName, vulnName) {
					libSuppressed.Add(1)
					continue
				}
				classProbs := make(map[string]float32, len(pred.ClassProbs))
				for i, prob := range pred.ClassProbs {
					classProbs[gnn.VulnClassName(gnn.VulnClass(i))] = prob
				}
				finding := types.GNNFinding{
					Method:     methodCFG.FullName,
					FilePath:   e.file.RelPath,
					VulnClass:  vulnName,
					Confidence: pred.Confidence,
					ClassProbs: classProbs,
					Dummy:      dummyModel,
				}
				mu.Lock()
				findings = append(findings, finding)
				mu.Unlock()
				accepted.Add(1)
				if isChainFallback {
					chainAccepted.Add(1)
				}
			}
		}()
	}

	// Feed jobs, honoring cancellation (previously Ctrl+C was ignored here).
	feedStopped := feedGNNJobs(workCtx, jobs, entries)
	cancelled := feedStopped && ctx.Err() != nil
	close(jobs)
	wg.Wait()
	if model != nil {
		model.Close()
	}

	// Deterministic output order.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].FilePath != findings[j].FilePath {
			return findings[i].FilePath < findings[j].FilePath
		}
		return findings[i].Method < findings[j].Method
	})
	for _, f := range findings {
		a.output.Info("GNN found %s in %s (confidence: %.2f)", f.VulnClass, f.Method, f.Confidence)
	}
	if dups := memo.Hits(); dups > 0 {
		a.output.Info("GNN memo: %d duplicate graph(s) reused results, %d unique graph(s) computed", dups, memo.Unique())
	}
	if cache != nil {
		st := cache.Stats()
		a.output.Info("GNN cache: %d hit(s), %d new prediction(s) stored, %.1f MB cache on disk", cacheHits.Load(), cacheStores.Load(), float64(st.DiskBytes)/(1024*1024))
		if st.DiskEvictions > 0 {
			a.output.Info("GNN cache: %d disk eviction(s); consider raising the content cache disk limit", st.DiskEvictions)
		}
		if st.HotEvictions > 0 {
			// Memory pressure, not disk pressure: keep the two apart so the
			// disk-limit hint above stays truthful.
			a.output.Info("GNN cache: %d in-memory eviction(s), %.1f MB resident", st.HotEvictions, float64(st.HotBytes)/(1024*1024))
		}
		if rej := cache.Rejections(); rej.Total > 0 {
			a.output.Warning(
				"GNN cache rejected and purged %d entries (malformed: %d, schema: %d, key mismatch: %d, invalid prediction: %d, integrity: %d)",
				rej.Total, rej.Malformed, rej.Schema, rej.Key, rej.Invalid, rej.Integrity,
			)
		}
		if st.CorruptEntries > 0 {
			a.output.Warning("GNN cache dropped %d corrupt on-disk record(s) failing the checksum", st.CorruptEntries)
		}
		if skipped := bodylessSkipped.Load(); skipped > 0 {
			a.output.Info("GNN cache: %d graph(s) had no recoverable method body and were not persisted", skipped)
		}
		if failures := cacheFailures.Load(); failures > 0 {
			a.output.Warning("GNN cache failed to store %d prediction(s)", failures)
		}
	}
	if skipped := cfglessSkipped.Load(); skipped > 0 {
		a.output.Info(
			"GNN skipped %d method(s) with no usable control-flow graph (need at least %d nodes)",
			skipped, gnnMinGraphNodes,
		)
	}
	if fb := chainFallback.Load(); fb > 0 {
		a.output.Info(
			"GNN chain-fallback: %d straight-line method(s) classified as instruction chains (%d accepted as findings)",
			fb, chainAccepted.Load(),
		)
	}
	if skipped := oversizedSkipped.Load(); skipped > 0 {
		a.output.Warning(
			"GNN skipped %d oversized method/graph(s) (limits: %d instructions, %d nodes, %d edges)",
			skipped, gnnMaxMethodInstructions, gnnMaxGraphNodes, gnnMaxGraphEdges,
		)
	}
	if failures := datasetFailures.Load(); failures > 0 {
		a.output.Warning("GNN dataset failed to store %d example(s)", failures)
	}
	if datasetFull.Load() {
		a.output.Warning("GNN dataset directory reached its size cap; new training examples are not recorded")
	}
	if fails := inferFails.Load(); fails > 0 {
		a.output.Warning("GNN inference failed for %d method(s); their results are missing", fails)
	}
	if reviewed := accepted.Load() + uncertain.Load(); reviewed > 0 {
		a.output.Info(
			"GNN quality gate: %d finding(s) accepted, %d uncertain prediction(s) rejected (top-two margin >= %.2f, normalized entropy <= %.2f; confidence is per-class)",
			accepted.Load(), uncertain.Load(), gnnMinMargin, gnnMaxNormalizedEntropy,
		)
	}
	if suppressed := libSuppressed.Load(); suppressed > 0 {
		a.output.Info(
			"GNN suppressed %d billing-library license-check prediction(s) (library internals, not findings)",
			suppressed,
		)
	}
	if others := otherClass.Load(); others > 0 {
		a.output.Info("GNN classified %d graph(s) as benign/non-vulnerable", others)
	}
	if cancelled {
		a.output.Warning("GNN classification cancelled: only a subset of %d method(s) was processed", len(entries))
	}

	result.GNNFindings = findings
	if dummyModel && len(findings) > 0 {
		a.output.Warning("GNN: %d finding(s) came from DUMMY weights — they are flagged dummy, contribute no evidence to verdicts, and must be ignored in patch planning", len(findings))
	}
	if firstLoadErr != nil {
		return fmt.Errorf("failed to load GNN model: %w", firstLoadErr)
	}
	return nil
}
