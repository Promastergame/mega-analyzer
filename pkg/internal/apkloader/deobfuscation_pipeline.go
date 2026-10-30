package apkloader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DEOBFUSCATION PIPELINE (Hyperion v3.0)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Orchestrates the entire deobfuscation process for an APK:
//   1. Loading & Parsing (DEX)
//   2. Intermediate Representation (MIR)
//   3. Control Flow Analysis (CFG)
//   4. Data Flow Analysis (SSA)
//   5. Optimization Passes (CP, DCE, OPR, Pattern)
//   6. Name Recovery (Variable, Method)
//   7. Code Generation (Pretty Smali)
//
// Optimized for performance via the OptimizationCoordinator and
// hardened via the RobustnessHandler.

// PipelineConfig defines the behavior of the deobfuscation pipeline.
type PipelineConfig struct {
	EnableConstantPropagation    bool
	EnableDeadCodeElimination    bool
	EnableOpaquePredicateRemoval bool
	EnablePatternSimplification  bool
	EnableVariableRecovery       bool
	EnableMethodRecovery         bool
	EnableReflectionResolution   bool
	EnableNameQualityAnalysis    bool
	MaxIterations                int
	MinConfidenceThreshold       int
	UseRustDeobfuscator          bool
	// ── Rust FFI offload flags (plan_dex_loader v11.0 task #3) ─────────
	// All three are opt-in. When `true` the pipeline will hand the work
	// to Rust; on any failure (DLL missing, decode error, empty result)
	// it transparently falls back to the in-process Go implementation.
	EnableControlFlowDeflattening bool
	EnableMBASimplification       bool
	UseRustCFFDeflattening        bool // offload CFF to Rust via FFI
	UseRustMBASimplify            bool // offload MBA to Rust via FFI
	UseRustCFG                    bool // offload CFG construction to omnisec-cfg
	UseRustSymbolic               bool // offload symbolic execution to omnisec-analysis-symbolic
	UseRustVirtDetection          bool // offload virtualization detection to omnisec-analysis-virt
	EnableDalvikEmulator          bool
	DalvikEmulatorConfig          DalvikEmulatorConfig
	ParallelConfig                *ParallelConfig
	// MaxRetainedSmaliBytes caps pretty-printed Smali kept in PipelineResult
	// (0 = defaultMaxRetainedSmaliBytes). Metrics and transformation journals
	// are unaffected — only the human-readable class dumps are dropped once
	// the budget is exhausted, so a 6k-class DEX cannot pin unbounded dumps.
	MaxRetainedSmaliBytes int64
}

// DefaultPipelineConfig returns the recommended pipeline configuration.
func DefaultPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		EnableConstantPropagation:    true,
		EnableDeadCodeElimination:    true,
		EnableOpaquePredicateRemoval: true,
		EnablePatternSimplification:  true,
		EnableVariableRecovery:       true,
		EnableMethodRecovery:         true,
		EnableReflectionResolution:   true,
		EnableNameQualityAnalysis:    true,
		MaxIterations:                5,
		MinConfidenceThreshold:       50,
		UseRustDeobfuscator:          true,
		// Rust CFG is default-on after parity tests; symbolic and virt detection
		// remain opt-in because they depend on heavier native artifacts.
		EnableControlFlowDeflattening: true,
		EnableMBASimplification:       true,
		UseRustCFFDeflattening:        true,
		UseRustMBASimplify:            true,
		UseRustCFG:                    true,
		UseRustSymbolic:               false,
		UseRustVirtDetection:          false,
		EnableDalvikEmulator:          true,
		DalvikEmulatorConfig:          DefaultDalvikEmulatorConfig(),
		ParallelConfig:                DefaultParallelConfig(),
		MaxRetainedSmaliBytes:         defaultMaxRetainedSmaliBytes,
	}
}

// PipelineResult contains the statistics and artifacts of a pipeline run.
type PipelineResult struct {
	StartTime           time.Time
	Duration            time.Duration
	MethodsProcessed    int
	Errors              int
	Warnings            int
	RecoveryRate        float64
	ReductionPercent    float64
	TotalTransforms     int                               `json:"total_transforms"`
	FoldedConstants     int                               `json:"folded_constants"`
	FoldedBranches      int                               `json:"folded_branches"`
	RemovedBlocks       int                               `json:"removed_blocks"`
	Transformations     []TransformEntry                  `json:"transformations,omitempty"`
	MethodMetrics       map[string]MethodTransformMetrics `json:"method_metrics,omitempty"`
	DeobfuscatedClasses map[string]string                 // class name -> pretty smali
	// SmaliBudgetBytes caps retained pretty Smali (0 = default). Dumps beyond
	// the budget are dropped and counted in DroppedSmaliClasses; metrics and
	// journals are always kept.
	SmaliBudgetBytes    int64 `json:"smali_budget_bytes,omitempty"`
	DroppedSmaliClasses int   `json:"dropped_smali_classes,omitempty"`

	// Builders remain private until the pipeline is complete, avoiding O(n²)
	// copies from repeated string concatenation for transformed classes.
	deobfuscatedClassBuilders map[string]*strings.Builder
	// smaliRetainedBytes tracks retained dump bytes against SmaliBudgetBytes.
	// Like the builders map, it assumes the caller serializes appends (the
	// batch path holds the coordinator lock).
	smaliRetainedBytes int64
}

// defaultMaxRetainedSmaliBytes caps pretty-printed Smali retained per pipeline
// result: 32 MiB of dumps is plenty for review, while a paranoid run over a
// 6k-class DEX could otherwise pin 10-100 MiB of text.
const defaultMaxRetainedSmaliBytes = 32 << 20

// smaliBudget returns the effective retention budget for results produced by
// this pipeline.
func (p *DeobfuscationPipeline) smaliBudget() int64 {
	if p != nil && p.Config != nil && p.Config.MaxRetainedSmaliBytes > 0 {
		return p.Config.MaxRetainedSmaliBytes
	}
	return defaultMaxRetainedSmaliBytes
}

func newPipelineResult() *PipelineResult {
	return &PipelineResult{
		StartTime:                 time.Now(),
		DeobfuscatedClasses:       make(map[string]string),
		MethodMetrics:             make(map[string]MethodTransformMetrics),
		deobfuscatedClassBuilders: make(map[string]*strings.Builder),
		SmaliBudgetBytes:          defaultMaxRetainedSmaliBytes,
	}
}

func (r *PipelineResult) appendDeobfuscatedSmali(className, smali string) {
	if smali == "" {
		return
	}
	budget := r.SmaliBudgetBytes
	if budget <= 0 {
		budget = defaultMaxRetainedSmaliBytes
	}
	if r.smaliRetainedBytes+int64(len(smali)) > budget {
		r.DroppedSmaliClasses++
		return
	}
	if r.deobfuscatedClassBuilders == nil {
		r.deobfuscatedClassBuilders = make(map[string]*strings.Builder)
	}
	builder := r.deobfuscatedClassBuilders[className]
	if builder == nil {
		builder = &strings.Builder{}
		r.deobfuscatedClassBuilders[className] = builder
	}
	_, _ = builder.WriteString(smali)
	r.smaliRetainedBytes += int64(len(smali))
}

func (r *PipelineResult) finalizeDeobfuscatedClasses() {
	if len(r.deobfuscatedClassBuilders) == 0 {
		return
	}
	if r.DeobfuscatedClasses == nil {
		r.DeobfuscatedClasses = make(map[string]string, len(r.deobfuscatedClassBuilders))
	}
	for className, builder := range r.deobfuscatedClassBuilders {
		r.DeobfuscatedClasses[className] = builder.String()
	}
	// Strings returned by Builder.String retain their backing storage; dropping
	// the builder map releases metadata without making another content copy.
	r.deobfuscatedClassBuilders = nil
}

// DeobfuscationPipeline orchestrates the deobfuscation workflow.
type DeobfuscationPipeline struct {
	Config           *PipelineConfig
	Robustness       *RobustnessHandler
	Coordinator      *OptimizationCoordinator
	Extractor        *Extractor
	ProgressCallback ProgressCallback
}

// NewDeobfuscationPipeline creates a new deobfuscation pipeline.
func NewDeobfuscationPipeline(config *PipelineConfig) *DeobfuscationPipeline {
	if config == nil {
		config = DefaultPipelineConfig()
	}
	return &DeobfuscationPipeline{
		Config:      config,
		Robustness:  NewRobustnessHandler(),
		Coordinator: NewOptimizationCoordinator(config.ParallelConfig),
		Extractor:   NewExtractor(),
	}
}

// ProcessAPK runs the deobfuscation pipeline on an APK.
func (p *DeobfuscationPipeline) ProcessAPK(ctx context.Context, apkPath string) (*PipelineResult, error) {
	result := newPipelineResult()
	result.SmaliBudgetBytes = p.smaliBudget()

	// Step 1: Extract APK
	extractedDir, err := p.Extractor.PrepareInput(ctx, apkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare input: %w", err)
	}
	defer os.RemoveAll(extractedDir)

	// Step 2: Find and parse DEX files
	dexFiles, _ := filepath.Glob(filepath.Join(extractedDir, "*.dex"))
	if len(dexFiles) == 0 {
		return nil, fmt.Errorf("no DEX files found in %s", apkPath)
	}

	if p.ProgressCallback != nil {
		p.Coordinator.methodAnalyzer.ProgressCallback = p.ProgressCallback
	}

	// Process one DEX at a time. Keeping all parsers and tasks until the end made
	// peak memory grow with the number of DEX files rather than the worker budget.
	processedMethods := 0
	var processingErr error
	for _, dexFile := range dexFiles {
		parser, parseErr := ParseDEX(dexFile)
		if parseErr != nil {
			p.Robustness.RecordError(&PipelineErrorInfo{
				Severity:    PipelineSeverityWarning,
				Component:   "DEXParser",
				Message:     fmt.Sprintf("Failed to parse %s: %v", dexFile, parseErr),
				Recoverable: true,
			})
			continue
		}

		tasks := make([]*MethodAnalysisTask, 0)
		for _, cls := range parser.GetClasses() {
			for _, method := range cls.DirectMethods {
				if method.Code != nil {
					tasks = append(tasks, &MethodAnalysisTask{ClassName: cls.ClassName, MethodName: method.Name, Method: method})
				}
			}
			for _, method := range cls.VirtualMethods {
				if method.Code != nil {
					tasks = append(tasks, &MethodAnalysisTask{ClassName: cls.ClassName, MethodName: method.Name, Method: method})
				}
			}
		}

		processingErr = p.Coordinator.AnalyzeMethodsOptimized(tasks, func(task *MethodAnalysisTask) error {
			return p.transformTaskMethod(ctx, task, result)
		})
		processedMethods += len(tasks)
		// Release DEX backing data before the next multi-dex shard is parsed.
		_ = parser.Close()
		if processingErr != nil {
			break
		}
	}

	result.finalizeDeobfuscatedClasses()
	result.Duration = time.Since(result.StartTime)
	result.MethodsProcessed = processedMethods

	stats := p.Robustness.GetStatistics()
	result.Errors = stats.TotalErrors
	result.Warnings = stats.WarningCount
	if result.MethodsProcessed > 0 {
		transformedMethods := make(map[string]struct{})
		for _, tr := range result.Transformations {
			transformedMethods[tr.ClassName+"->"+tr.MethodName] = struct{}{}
		}
		result.RecoveryRate = 100 * float64(len(transformedMethods)) / float64(result.MethodsProcessed)
	}
	totalStructuralChanges := result.TotalTransforms + result.RemovedBlocks
	if totalStructuralChanges > 0 {
		result.ReductionPercent = 100 * float64(result.RemovedBlocks) / float64(totalStructuralChanges)
	}

	return result, processingErr
}

// MethodTransformMetrics measures the actual graph and proof changes made by
// Hyperion. Candidate triage is intentionally separate from transformation.
type MethodTransformMetrics struct {
	BlocksBefore    int  `json:"blocks_before"`
	BlocksAfter     int  `json:"blocks_after"`
	EdgesBefore     int  `json:"edges_before"`
	EdgesAfter      int  `json:"edges_after"`
	InsnsBefore     int  `json:"instructions_before"`
	InsnsAfter      int  `json:"instructions_after"`
	FoldedConstants int  `json:"folded_constants,omitempty"`
	FoldedBranches  int  `json:"folded_branches,omitempty"`
	RemovedBlocks   int  `json:"removed_blocks,omitempty"`
	ProofsAccepted  int  `json:"proofs_accepted,omitempty"`
	BudgetExhausted bool `json:"budget_exhausted,omitempty"`
}

// OwnedMethodTransformResult is the worker-safe output of processing one
// immutable OwnedDEXMethod. Transformed is true only when accepted journal
// proofs or measured structural removals exist.
type OwnedMethodTransformResult struct {
	ClassName        string                 `json:"class_name"`
	MethodName       string                 `json:"method_name"`
	CandidateScore   int                    `json:"candidate_score,omitempty"`
	CandidateReasons []string               `json:"candidate_reasons,omitempty"`
	Transformed      bool                   `json:"transformed"`
	Smali            string                 `json:"smali,omitempty"`
	Journal          []TransformEntry       `json:"journal,omitempty"`
	Metrics          MethodTransformMetrics `json:"metrics"`
	Emulation        DalvikEmulationResult  `json:"emulation,omitempty"`
	RecoveredValues  []DalvikRecoveredValue `json:"recovered_values,omitempty"`
}

// ProcessOwnedMethod runs Hyperion directly on parser-detached DEX data. It
// never opens or reparses the APK/DEX and is therefore safe for production DEX
// workers after the lazy parser has released the original CodeItem.
func (p *DeobfuscationPipeline) ProcessOwnedMethod(ctx context.Context, method OwnedDEXMethod) (*OwnedMethodTransformResult, error) {
	return p.ProcessOwnedMethodWithResolver(ctx, method, nil)
}

// ProcessOwnedMethodWithResolver preserves structural processing of the root
// while allowing the bounded emulator to summarize owned app-defined callees.
func (p *DeobfuscationPipeline) ProcessOwnedMethodWithResolver(ctx context.Context, method OwnedDEXMethod, resolver *OwnedMethodResolver) (*OwnedMethodTransformResult, error) {
	return p.ProcessOwnedMethodWithEnvironment(ctx, method, resolver, nil)
}

// ProcessOwnedMethodWithEnvironment supplies immutable method and static-field
// snapshots to the bounded emulator while structural passes still process only
// the root method.
func (p *DeobfuscationPipeline) ProcessOwnedMethodWithEnvironment(ctx context.Context, method OwnedDEXMethod, resolver *OwnedMethodResolver, statics *OwnedStaticResolver) (*OwnedMethodTransformResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if method.Code == nil || len(method.RawInsns) == 0 {
		return &OwnedMethodTransformResult{
			ClassName: method.ClassName, MethodName: method.MethodName,
			CandidateScore:   method.CandidateScore,
			CandidateReasons: append([]string(nil), method.CandidateReasons...),
		}, nil
	}
	result := &PipelineResult{
		DeobfuscatedClasses:       make(map[string]string),
		MethodMetrics:             make(map[string]MethodTransformMetrics),
		deobfuscatedClassBuilders: make(map[string]*strings.Builder),
		SmaliBudgetBytes:          p.smaliBudget(),
	}
	if err := p.processRawMethod(ctx, method.ClassName, method.MethodName, method.RawInsns, method.Code, result); err != nil {
		return nil, err
	}
	result.finalizeDeobfuscatedClasses()
	metrics := measureMethodTransform(result, method.ClassName, method.MethodName)
	emulation := DalvikEmulationResult{Status: DalvikEmulationNoOutput, StopReason: "emulator disabled"}
	if p.Config.EnableDalvikEmulator {
		emulation = EmulateOwnedMethodWithEnvironment(ctx, method, resolver, statics, p.Config.DalvikEmulatorConfig)
		if emulation.Status == DalvikEmulationCancelled {
			return nil, ctx.Err()
		}
	}
	return &OwnedMethodTransformResult{
		ClassName: method.ClassName, MethodName: method.MethodName,
		CandidateScore:   method.CandidateScore,
		CandidateReasons: append([]string(nil), method.CandidateReasons...),
		Transformed:      metrics.ProofsAccepted > 0 || metrics.RemovedBlocks > 0,
		Smali:            result.DeobfuscatedClasses[method.ClassName],
		Journal:          append([]TransformEntry(nil), result.Transformations...),
		Metrics:          metrics,
		Emulation:        emulation,
		RecoveredValues:  append([]DalvikRecoveredValue(nil), emulation.RecoveredValues...),
	}, nil
}

// processMethod is the standalone single-method entry point. It runs the shared
// transform core and then finalizes the aggregated Smali, so callers that invoke
// it directly (outside the ProcessAPK batch, which finalizes once after all
// parallel workers) observe a fully populated DeobfuscatedClasses map.
func (p *DeobfuscationPipeline) processMethod(ctx context.Context, task *MethodAnalysisTask, result *PipelineResult) error {
	if err := p.transformTaskMethod(ctx, task, result); err != nil {
		return err
	}
	result.finalizeDeobfuscatedClasses()
	return nil
}

// transformTaskMethod decodes a task's method IR and runs the shared transform
// core WITHOUT finalizing. ProcessAPK calls this from parallel workers and
// finalizes exactly once after the batch, avoiding a concurrent finalize race
// and last-writer-wins overwrites across a class's methods.
func (p *DeobfuscationPipeline) transformTaskMethod(ctx context.Context, task *MethodAnalysisTask, result *PipelineResult) error {
	if task == nil || task.Method == nil || task.Method.Code == nil {
		return nil
	}
	return p.processRawMethod(ctx, task.ClassName, task.MethodName, DecodeMethodIR(task.Method.Code.Insns, nil), task.Method.Code, result)
}

func (p *DeobfuscationPipeline) processRawMethod(ctx context.Context, className, methodName string, rawInsns []RawInsn, code *CodeItem, result *PipelineResult) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// 1-2. Owned inputs are already decoded; lower them to Hyperion MIR.
	mirInsns := LowerToMIR(rawInsns)

	// 3. Build CFG (optionally offloaded to Rust; falls back to Go on any failure)
	cfg := BuildCFGWithHandlers(mirInsns, code)
	before := snapshotCFG(cfg)
	if p.Config.UseRustCFG {
		// We still need the Go CFG for SSA / downstream passes — but we
		// can use the Rust CFG as a sanity / parity oracle. The result
		// is intentionally discarded today; it only feeds telemetry and
		// keeps the FFI path warm. Any failure is a no-op fall-through.
		_, _ = OffloadBuildCFG(mirInsns)
	}

	if p.Config.EnableControlFlowDeflattening && p.Config.UseRustCFFDeflattening {
		if cffResult, ok := OffloadCFFDeflattening(cfg, mirInsns); ok && cffResult.Applied {
			// Rebuild CFG after deflattening rewrote edges
			cfg = BuildCFGWithHandlers(mirInsns, code)
			result.Transformations = append(result.Transformations, TransformEntry{
				ClassName: className, MethodName: methodName,
				Pass: "cff-deflattening",
				Proof: fmt.Sprintf("confidence=%d%% proven_edges=%d",
					cffResult.Confidence, len(cffResult.ProvenEdges)),
			})
		}
	}

	// 4. Build SSA and bind all following passes to one transforming session.
	// The session rebuilds graph metadata/SSA after control-flow changes and
	// keeps an exact journal of every proven rewrite.
	session := NewTransformSession(cfg)
	ssa := session.SSA

	// 4b. Optional Rust-side symbolic execution / virt-detection. Both
	//     are read-only telemetry today: callers can wire their results
	//     into reports later without changing the deopt pipeline shape.
	if p.Config.UseRustSymbolic {
		_, _ = OffloadSymbolicExecute(cfg, ssa, 10, 100)
	}
	if p.Config.UseRustVirtDetection {
		_, _ = OffloadDetectVirtualization(cfg, 50)
	}

	// 5. Optimization loop. Rust currently returns telemetry only; it must not
	// bypass the Go transformation passes until the FFI returns transformed MIR.
	if p.Config.UseRustDeobfuscator {
		_, _ = DeobfuscateWithRust(mirInsns, 1)
	}

	library := NewPatternLibrary()
	for i := 0; i < p.Config.MaxIterations; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		changed := false

		if p.Config.EnableConstantPropagation {
			if session.FoldLocalConstants(className, methodName) > 0 {
				changed = true
			}
		}

		// The legacy analysis still supplies proofs for self-comparisons. Apply
		// only predicates whose result is statically proven, then immediately
		// rebuild CFG/SSA before another pass consumes the graph.
		if p.Config.EnableOpaquePredicateRemoval {
			propResult := ConstantPropagation(session.CFG, session.SSA)
			oprResult := AnalyzeOpaquePredicates(session.CFG, propResult)
			proved := oprResult.TotalOpaquePredicates()
			if proved > 0 {
				oprResult.RemoveOpaquePredicates(session.CFG)
				session.RebuildAnalysis()
				changed = true
			}
		}

		if p.Config.EnableDeadCodeElimination {
			beforeBlocks := len(session.CFG.Blocks)
			dceResult := AnalyzeDeadCode(session.CFG, session.SSA)
			if dceResult != nil && dceResult.Changes > 0 {
				dceResult.RemoveDeadCode(session.CFG)
				session.RebuildAnalysis()
				removed := beforeBlocks - len(session.CFG.Blocks)
				if removed > 0 {
					p.Coordinator.mu.Lock()
					result.RemovedBlocks += removed
					p.Coordinator.mu.Unlock()
				}
				changed = true
			}
		}

		if p.Config.EnablePatternSimplification {
			psResult := PatternSimplification(session.CFG, library)
			if psResult != nil && psResult.Changes > 0 {
				session.RebuildAnalysis()
				changed = true
			}
		}

		if p.Config.EnableReflectionResolution {
			dclResolver := NewDynamicCodeLoadingResolver(session.CFG, session.SSA)
			dclResolver.DetectDynamicCodeLoading()
		}

		if !changed {
			break
		}
	}
	cfg, ssa = session.CFG, session.SSA

	// 6. Name Recovery
	var vr *VariableRecovery
	if p.Config.EnableVariableRecovery {
		vr = NewVariableRecovery(cfg, ssa)
		vr.RecoverVariableNames()
	}

	// 7. Code Generation
	generator := NewPrettySmaliGenerator(cfg, ssa)
	generator.VariableRecovery = vr
	generator.MinConfidenceThreshold = p.Config.MinConfidenceThreshold
	generator.MethodName = methodName
	// Note: FoldLocalConstants mutates each folded instruction's Imm in place
	// on the CFG that GenerateSmali walks, so formatInstructionKind already
	// renders the correct per-instruction value from insn.Imm directly.
	// Bulk-importing journal entries into the register-keyed ConstantPropagation
	// map here would overwrite earlier blocks' values with the last block's for
	// any reused register — leave that map for callers with data (e.g. decoded
	// strings) that can't be represented as an instruction's int64 Imm.
	smaliOutput := generator.GenerateSmali()
	after := snapshotCFG(session.CFG)
	removedBlocks := before.blocks - after.blocks
	if removedBlocks < 0 {
		removedBlocks = 0
	}

	// Store only measured changes. Pretty Smali is retained for transformed
	// methods, while unchanged candidates remain an auditable abstention.
	p.Coordinator.mu.Lock()
	if result.MethodMetrics == nil {
		result.MethodMetrics = make(map[string]MethodTransformMetrics)
	}
	result.MethodMetrics[className+"->"+methodName] = MethodTransformMetrics{
		BlocksBefore: before.blocks, BlocksAfter: after.blocks,
		EdgesBefore: before.edges, EdgesAfter: after.edges,
		InsnsBefore: before.insns, InsnsAfter: after.insns,
		RemovedBlocks: removedBlocks, ProofsAccepted: len(session.Journal),
	}
	if len(session.Journal) > 0 || removedBlocks > 0 {
		result.appendDeobfuscatedSmali(className, smaliOutput.Code)
	}
	result.Transformations = append(result.Transformations, session.Journal...)
	result.TotalTransforms += len(session.Journal)
	result.RemovedBlocks += removedBlocks
	for _, tr := range session.Journal {
		switch tr.Pass {
		case "constant-fold":
			result.FoldedConstants++
		case "branch-fold":
			result.FoldedBranches++
		}
	}
	p.Coordinator.mu.Unlock()

	return nil
}

type cfgSnapshot struct {
	blocks int
	edges  int
	insns  int
}

func snapshotCFG(cfg *CFG) cfgSnapshot {
	var out cfgSnapshot
	if cfg == nil {
		return out
	}
	out.blocks = len(cfg.Blocks)
	for _, block := range cfg.Blocks {
		if block == nil {
			continue
		}
		out.edges += len(block.Succs)
		out.insns += len(block.Insns)
	}
	return out
}

func measureMethodTransform(result *PipelineResult, className, methodName string) MethodTransformMetrics {
	metrics := result.MethodMetrics[className+"->"+methodName]
	for _, tr := range result.Transformations {
		if tr.ClassName != className || tr.MethodName != methodName {
			continue
		}
		metrics.ProofsAccepted++
		switch tr.Pass {
		case "constant-fold":
			metrics.FoldedConstants++
		case "branch-fold":
			metrics.FoldedBranches++
		}
	}
	return metrics
}
