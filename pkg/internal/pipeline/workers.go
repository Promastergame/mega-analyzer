// pkg/internal/pipeline/workers.go
package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"
	"unsafe"

	"mega-analyzer/pkg/internal/analyzer"
	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/boundedfile"
	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/contentcache"
	deobfuscator "mega-analyzer/pkg/internal/deobfuscation"
	dexiradapters "mega-analyzer/pkg/internal/dexir/adapters"
	"mega-analyzer/pkg/internal/parser"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"
	"mega-analyzer/pkg/media"
	"sync"
	"sync/atomic"
)

// fileBuffer owns one immutable file body and computes expensive derived views
// only when the selected scanners need them. String views are zero-copy and are
// valid for the lifetime of the backing byte slice.
type fileBuffer struct {
	raw       []byte
	lower     []byte
	lowerMade bool
	lines     *types.LineOffsets
	pooled    *[]byte
}

// lowerBufferPool recycles the lowercase copies of file bodies. Ownership was
// audited in Phase 2: every consumer of the lowercase view either compares in
// place (matcher.prefilterPatterns, findXMLSuspicious, detectXMLAnalytics) or
// copies before retaining (string(ctx.ContentLower...)). No result field
// aliases it: Match.Text/Context are cut from the raw body, not from the
// lowercase one. The buffer is released at the end of processContent.
var lowerBufferPool = sync.Pool{New: func() any { b := make([]byte, 0, 64*1024); return &b }}

// lowerPoolMaxCap keeps pathological multi-MB one-offs out of the pool.
const lowerPoolMaxCap = 8 << 20

func newFileBuffer(raw []byte) *fileBuffer { return &fileBuffer{raw: raw} }

// release returns the pooled lowercase buffer. After this call no []byte or
// unsafe.String view obtained from Lower()/LowerString() may be used.
func (b *fileBuffer) release() {
	if b.pooled != nil {
		if cap(*b.pooled) <= lowerPoolMaxCap {
			*b.pooled = (*b.pooled)[:0]
			lowerBufferPool.Put(b.pooled)
		}
		b.pooled = nil
	}
	b.lower = nil
	b.lowerMade = false
}

func (b *fileBuffer) Bytes() []byte { return b.raw }

func (b *fileBuffer) Lower() []byte {
	if !b.lowerMade {
		b.lower = b.lowerInto(b.raw)
		b.lowerMade = true
	}
	return b.lower
}

// lowerInto lowercases raw into a pooled destination. Non-ASCII input keeps the
// bytes.ToLower fallback (unpooled), so behaviour is identical to lowerASCII.
func (b *fileBuffer) lowerInto(raw []byte) []byte {
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 0x80 {
			return bytes.ToLower(raw)
		}
	}
	if len(raw) == 0 {
		return nil
	}
	p := lowerBufferPool.Get().(*[]byte)
	if cap(*p) < len(raw) {
		*p = make([]byte, len(raw))
	}
	dst := (*p)[:len(raw)]
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst[i] = c
	}
	b.pooled = p
	return dst
}

// lowerASCII lowercases ASCII input in one pass, skipping the rune decoding
// bytes.ToLower performs. Non-ASCII input falls back to bytes.ToLower, so
// behaviour is identical. The destination buffer is deliberately NOT pooled:
// it is handed to detectors as an unsafe.String and its lifetime has not been
// audited yet (Phase 2 owns that).
func lowerASCII(raw []byte) []byte {
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 0x80 {
			return bytes.ToLower(raw)
		}
	}
	out := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func (b *fileBuffer) String() string {
	if len(b.raw) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b.raw), len(b.raw))
}

func (b *fileBuffer) LowerString() string {
	lower := b.Lower()
	if len(lower) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(lower), len(lower))
}

func (b *fileBuffer) LineOffsets() *types.LineOffsets {
	if b.lines == nil {
		b.lines = types.NewLineOffsets(b.raw)
	}
	return b.lines
}

// ═══════════════════════════════════════════════════════════════════════════════
// WORKER
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) worker(ctx context.Context, jobs <-chan FileJob, results chan<- *types.FileAnalysis) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case job, ok := <-jobs:
			if !ok {
				return nil
			}
			p.processJobSafe(ctx, job, results)
		}
	}
}

// processJobSafe оборачивает processFile в panic recovery.
func (p *Pipeline) processJobSafe(ctx context.Context, job FileJob, results chan<- *types.FileAnalysis) {
	p.startActiveJob(job)
	defer p.finishActiveJob(job.RelPath)
	// FilesProcessed counts physical jobs, including parse failures and
	// recovered panics. Keeping this in a defer prevents a permanently stuck
	// 99% bar when the final job fails before the normal return path.
	defer p.stats.FilesProcessed.Add(1)
	isDEX := job.Type == types.FileTypeDex && strings.EqualFold(filepath.Ext(job.Path), ".dex")
	if !isDEX {
		defer p.stats.WorkProcessed.Add(1)
	}
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Worker panic recovered",
				"file", job.RelPath,
				"panic", r,
				"stack", string(debug.Stack()),
			)
			p.stats.ErrorCount.Add(1)
			p.stats.FilesFailed.Add(1)
		}
	}()

	start := time.Now()
	defer func() { p.recordSlowFile(job.RelPath, time.Since(start)) }()

	if isDEX {
		p.updateActiveJob(job.RelPath, "parsing DEX", 0, 0)
		p.processDEXJob(ctx, job, results)
		return
	}

	analysis := p.processFile(ctx, job)
	p.sendAnalysis(ctx, results, analysis)
}

func (p *Pipeline) sendAnalysis(ctx context.Context, results chan<- *types.FileAnalysis, analysis *types.FileAnalysis) {
	if analysis == nil {
		return
	}
	select {
	case results <- analysis:
	case <-ctx.Done():
		// Cancellation: this result can no longer be delivered. Count it so
		// the run summary can honestly say the report is partial.
		p.stats.ResultsDropped.Add(1)
	}
}

// processDEXJob parses a physical DEX once and feeds one class IR at a time to
// the existing matchers/detectors. No Smali file or compact stream is written.
func (p *Pipeline) processDEXJob(ctx context.Context, job FileJob, results chan<- *types.FileAnalysis) {
	p.stats.BytesProcessed.Add(job.Size)

	type dexClassTask struct {
		className string
		ir        []byte
		methods   []apkloader.OwnedDEXMethod
		resolver  *apkloader.OwnedMethodResolver
		statics   *apkloader.OwnedStaticResolver
	}

	workerCount := p.effectiveWorkerCount()
	if workerCount < 1 {
		workerCount = 1
	}

	classChan := make(chan dexClassTask, workerCount*16)
	var wg sync.WaitGroup
	sem := p.dexClassSemaphore()
	var classesDone atomic.Int64
	var classesTotal atomic.Int64

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hyperionConfig := apkloader.DefaultPipelineConfig()
			hyperionConfig.MaxIterations = p.config.DeobfuscationOptions.MaxIterations
			if hyperionConfig.MaxIterations <= 0 {
				hyperionConfig.MaxIterations = 5
			}
			hyperionConfig.MinConfidenceThreshold = p.config.DeobfuscationOptions.MinConfidenceThreshold
			hyperionConfig.EnableConstantPropagation = p.config.DeobfuscationOptions.EnableCP
			hyperionConfig.EnableDeadCodeElimination = p.config.DeobfuscationOptions.EnableDCE
			hyperionConfig.EnableOpaquePredicateRemoval = p.config.DeobfuscationOptions.EnableOPR
			hyperionConfig.EnablePatternSimplification = p.config.DeobfuscationOptions.EnablePS
			hyperionConfig.EnableVariableRecovery = p.config.DeobfuscationOptions.EnableVR
			hyperionConfig.EnableMethodRecovery = p.config.DeobfuscationOptions.EnableMR
			hyperionConfig.EnableNameQualityAnalysis = p.config.DeobfuscationOptions.EnableNameQuality
			hyperion := apkloader.NewDeobfuscationPipeline(hyperionConfig)
			for task := range classChan {
				select {
				case <-ctx.Done():
					return
				default:
				}
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				func() {
					defer func() {
						<-sem
						if r := recover(); r != nil {
							logger.Error("DEX class worker panic recovered",
								"file", job.RelPath, "class", task.className,
								"panic", r, "stack", string(debug.Stack()))
							p.stats.ErrorCount.Add(1)
							p.stats.ParseFailed.Add(1)
						}
						done := classesDone.Add(1)
						p.stats.WorkProcessed.Add(1)
						total := classesTotal.Load()
						if done == total || done%16 == 0 {
							p.updateActiveJob(job.RelPath, "DEX classes", done, total)
						}
					}()
					p.stats.ClassesAnalyzed.Add(1)
					p.stats.MethodsAnalyzed.Add(int64(bytes.Count(task.ir, []byte(".method "))))
					virtualJob := FileJob{
						Path: job.Path,
						// Use a conventional smali path only as an in-memory identity.
						// This lets the library/app classifier recognise Kotlin, AndroidX,
						// Google and other bundled SDK code instead of treating every DEX
						// class as application code. No .smali file is written.
						RelPath: dexClassVirtualPath(job.RelPath, task.className),
						Type:    types.FileTypeSmali,
						Size:    int64(len(task.ir)),
					}
					analysis := p.processContent(ctx, virtualJob, task.ir)
					if analysis != nil {
						// Report the real source format; Smali exists only as an in-memory
						// detector grammar and is never exposed as a generated file.
						analysis.Type = types.FileTypeDex
						if p.config.EnableDeobfuscation && len(task.methods) > 0 {
							recoveredBefore := len(analysis.RecoveredStrings)
							p.applyHyperionMethodsWithEnvironment(ctx, analysis, hyperion, task.methods, task.resolver, task.statics)
							if len(analysis.RecoveredStrings) > recoveredBefore {
								p.rescanRecoveredContent(ctx, analysis, virtualJob)
							}
						}
					}
					p.sendAnalysis(ctx, results, analysis)
				}()
			}
		}()
	}

	var irErr error
	if p.config.EnableDeobfuscation {
		// Streaming ownership: the cross-class environment (callee resolver,
		// statics) is built once with bounded budgets, then classes flow one
		// at a time through the worker queue. Peak memory no longer scales
		// with the number of classes in the DEX. IR buffers are fresh per
		// class, so ownership transfers to the queue with no extra copy.
		irErr = apkloader.StreamOwnedBundleFile(ctx, job.Path, apkloader.OwnedDEXOptions{
			EnableHyperion:      true,
			MinCandidateScore:   4,
			MaxReachableDepth:   3,
			MaxReachableMethods: 256,
			MaxOwnedCodeUnits:   1 << 20,
		}, func(class apkloader.DEXClassIR, env *apkloader.OwnedEnvironment) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case classChan <- dexClassTask{className: class.ClassName, ir: class.IR, methods: class.Methods, resolver: env.Resolver, statics: env.Statics}:
				return nil
			}
		}, func(done, total int) {
			classesTotal.Store(int64(total))
			p.updateActiveJob(job.RelPath, "DEX classes", classesDone.Load(), int64(total))
		})
	} else {
		irErr = apkloader.WalkDEXClassOwnedFileProgress(ctx, job.Path, apkloader.OwnedDEXOptions{}, func(class apkloader.DEXClassIR) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case classChan <- dexClassTask{className: class.ClassName, ir: class.IR}:
				return nil
			}
		}, func(done, total int) {
			if done == 0 {
				classesTotal.Store(int64(total))
				p.updateActiveJob(job.RelPath, "DEX classes", classesDone.Load(), int64(total))
			}
		})
	}

	close(classChan)
	wg.Wait()
	p.updateActiveJob(job.RelPath, "DEX classes", classesDone.Load(), classesTotal.Load())
	// A DEX with no class definitions is still one declared work unit. Likewise,
	// a malformed DEX can stop before all header-declared classes are emitted.
	// Finish the remainder once so fixed progress never stalls below 100%.
	if remaining := job.WorkUnits - classesDone.Load(); remaining > 0 {
		p.stats.WorkProcessed.Add(remaining)
	}

	if irErr != nil {
		p.stats.ErrorCount.Add(1)
		p.stats.ParseFailed.Add(1)
		// Malformed/unsupported DEX still gets a cheap raw signature pass.
		content, readErr := boundedfile.ReadFile(job.Path, 64<<20)
		if readErr != nil {
			p.stats.FilesFailed.Add(1)
			return
		}
		rawAnalysis := p.processContent(ctx, job, content)
		if rawAnalysis != nil {
			rawAnalysis.ParseError = irErr.Error()
		}
		p.sendAnalysis(ctx, results, rawAnalysis)
		return
	}
	p.stats.FilesParsed.Add(1)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROCESS FILE
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) processFile(ctx context.Context, job FileJob) *types.FileAnalysis {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	limit := int64(64 << 20)
	if fastLowerExt(job.RelPath) == ".svg" {
		limit = 8 << 20
	}
	content, err := boundedfile.ReadFile(job.Path, limit)
	if err != nil {
		p.stats.FilesFailed.Add(1)
		analysis := types.NewFileAnalysis(job.RelPath, job.Type, job.Size)
		analysis.ParseError = err.Error()
		m := newMatch(types.CategoryMediaAnomaly, job.RelPath, 1, "Content inspection skipped: bounded read failed", err.Error(), false)
		m.Metadata["rule_id"] = "analysis.bounded_read"
		analysis.Matches = append(analysis.Matches, m)
		return analysis
	}

	// A binary AndroidManifest.xml reaches this point only on the in-memory
	// APK path; the decoded-tree path already stores it as text. Normalising
	// it here keeps every manifest detector on one input format.
	content = decodeBinaryManifest(job.RelPath, job.Type, content)

	p.stats.FilesParsed.Add(1)
	if job.Type == types.FileTypeSmali {
		p.stats.ClassesAnalyzed.Add(1)
		p.stats.MethodsAnalyzed.Add(int64(bytes.Count(content, []byte(".method "))))
	}
	p.stats.BytesProcessed.Add(int64(len(content)))
	return p.processContent(ctx, job, content)
}

// suspiciousScoreThreshold returns the configured app-code suspicion cutoff.
// Phase 0 numbers: on the real APK the score maxed at 5.00 (0/11 files above
// the old hardcoded `> 5`), on synthetic smali the median was 36.00 (98.5% of
// files above it) - the cutoff is corpus-dependent and belongs in config.
// Zero-value configs keep the historical 5.
func (p *Pipeline) suspiciousScoreThreshold() float64 {
	if p.config != nil && p.config.SuspiciousScoreThreshold > 0 {
		return p.config.SuspiciousScoreThreshold
	}
	return 5
}

func (p *Pipeline) processContent(ctx context.Context, job FileJob, content []byte) *types.FileAnalysis {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	// Library names affect attribution and scoring, never whether untrusted
	// content reaches the parsers and security detectors.
	classification := p.filter.ClassifyForPipeline(job.RelPath)
	isAppCode := classification.IsAppCode || job.ForceAppCode

	buffer := newFileBuffer(content)
	// Every lowercase-view consumer either compares in place or copies; see
	// lowerBufferPool. Nothing survives this function, so recycle on all exits.
	defer buffer.release()
	analysis := types.NewFileAnalysis(job.RelPath, job.Type, job.Size)
	analysis.IsAppCode = isAppCode
	analysis.IsLibrary = classification.IsLibrary && !isAppCode
	analysis.Importance = classification.Importance
	scanContent := shouldScanContent(job.Type, content)
	var contentLower []byte
	if scanContent {
		contentLower = buffer.Lower()
	}
	if shouldIndexLines(job.Type, content) {
		analysis.LineOffsets = buffer.LineOffsets()
	}

	// Entropy
	if p.config.EnableEntropyAnalysis {
		analysis.Entropy = analyzer.CalculateEntropy(content)
	}

	// Pattern matching. Raw forensic data blobs (global-metadata.dat, save
	// files, analytics stores) are admitted only for the dedicated data/
	// detectors; the generic pattern matcher emits false positives on their
	// binary/cleartext contents, so skip it for them.
	forensicOnly := job.Type == types.FileTypeUnknown && isForensicDataFile(job.RelPath)
	var fileFuture fileScanFuture
	if p.fileExecutor != nil && !forensicOnly && (job.Type == types.FileTypeSmali ||
		job.Type == types.FileTypeXML || job.Type == types.FileTypeJSON ||
		job.Type == types.FileTypeText || job.Type == types.FileTypeProperties) {
		fileFuture = p.fileExecutor.Start(ctx, FileScanTask{Job: job, AppCode: isAppCode, Library: analysis.IsLibrary, Patterns: scanContent}, content)
	}
	if p.fileExecutor != nil {
		defer p.fileExecutor.Yield()
	}
	if scanContent && !forensicOnly && fileFuture == nil {
		t0pm := time.Now()
		analysis.Matches = p.matcher.MatchContentWithFilterLower(
			buffer.String(), buffer.LowerString(), job.RelPath, isAppCode,
		)
		p.stats.InternalTimings.PatternMatch.Record(time.Since(t0pm))
	}

	// ── Smali AST (parsed BEFORE detectors) ─────────────────────────────────
	// Structured detectors need per-method invokes/registers/string constants;
	// the AST must exist before the detector pass runs. Quick-APK preparation
	// emits concatenated detector streams that retain all textual signals but
	// are intentionally not a single parseable class — those keep the
	// byte-level path only.
	smaliCompact := job.Type == types.FileTypeSmali &&
		strings.Contains(filepath.ToSlash(job.RelPath), "smali_compact/")
	if job.Type == types.FileTypeSmali && !smaliCompact {
		p.processSmali(analysis, buffer.String())
	}

	var precomputedPiracy *[]types.Match
	var piracyDuration time.Duration
	var precomputedDetectors map[string]FileDetectorResult
	if fileFuture != nil {
		remote, err := fileFuture(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// A helper failure must never silently suppress evidence.
			logger.Warn("Browser file helper failed; scanning locally", "error", err)
			if scanContent {
				started := time.Now()
				matches := p.matcher.MatchContentWithFilterLower(buffer.String(), buffer.LowerString(), job.RelPath, isAppCode)
				analysis.Matches = append(matches, analysis.Matches...)
				p.stats.InternalTimings.PatternMatch.Record(time.Since(started))
			}
		} else {
			// Smali processing may already have added recovered-string findings.
			// Original pattern hits retain their original position before them.
			analysis.Matches = append(remote.Patterns, analysis.Matches...)
			precomputedPiracy = &remote.Piracy
			piracyDuration = time.Duration(remote.PiracyNs)
			precomputedDetectors = remote.Detectors
			if scanContent {
				p.stats.InternalTimings.PatternMatch.Record(time.Duration(remote.PatternNs))
			}
		}
	}

	// ── Детекторы ────────────────────────────────────────────────────────────
	dctx := &FileDetectContext{
		Ctx:                  ctx,
		Path:                 job.RelPath,
		Content:              content,
		ContentLower:         contentLower,
		LineOffsets:          analysis.LineOffsets,
		IsAppCode:            isAppCode,
		FileType:             job.Type,
		Job:                  job,
		Class:                analysis.SmaliClass,
		PrecomputedPiracy:    precomputedPiracy,
		PiracyDuration:       piracyDuration,
		PrecomputedDetectors: precomputedDetectors,
	}

	t0det := time.Now()
	p.runDetectors(dctx, analysis, job)
	p.stats.InternalTimings.Detectors.Record(time.Since(t0det))
	// P18c: the AST operand resolver outranks presence-only DYNAMIC_LOAD
	// pattern hits once every detector has contributed its matches.
	suppressPresenceOnlyDynamicLoad(dctx, analysis)

	// ── File-specific parsing ────────────────────────────────────────────────
	switch job.Type {
	case types.FileTypeSmali:
		if !smaliCompact {
			// Anything the deobfuscation engine recovered gets the same
			// detection treatment as the file's own content.
			p.rescanRecoveredContent(ctx, analysis, job)
		}
	case types.FileTypeXML:
		p.processXML(analysis, content, contentLower)
	case types.FileTypeMedia:
		engine := media.NewForensicEngine()
		res := engine.Analyze(content, job.RelPath, job.RelPath)
		analysis.MediaData = &res

		if res.RiskScore > 0 {
			// Compressed formats (MP3/OGG/PNG/JPEG/...) sit at entropy
			// 7.8–7.95 by design, so entropy-only findings there are expected
			// and never anomalous. Only corroborated signals (polyglot,
			// embedded executable/archive) may score such files.
			entropyExpected := isCompressedMediaPath(job.RelPath) ||
				media.IsExpectedHighEntropy(res.Classification.PrimaryFormat)
			hasRealThreat := res.Classification.IsPolyglot
			for _, r := range res.Regions {
				if r.FusedSeverity > 0.6 && regionHasCorroboratingSignal(r) {
					hasRealThreat = true
					break
				}
			}
			if !entropyExpected || hasRealThreat {
				analysis.SuspiciousScore += res.RiskScore
			}

			// A polyglot is itself a 2-signal finding: a valid image/media
			// header AND an embedded executable/archive format. Keep critical.
			if res.Classification.IsPolyglot {
				msg := "Detected polyglot: Primary=" + string(res.Classification.PrimaryFormat)
				if len(res.Classification.HiddenFormats) > 0 {
					msg += ", Hidden=" + string(res.Classification.HiddenFormats[0])
				}
				analysis.Matches = append(analysis.Matches, newMatch(
					types.CategoryMalware, analysis.Path, 1,
					"Media Polyglot", msg, true,
				))
			}

			// Per-region: require a SECOND corroborating signal before calling
			// a resource file malware. Compressed images legitimately reach
			// entropy 7.8–7.95, so "high entropy alone" is NOT a threat — it is
			// demoted to an informational Media Anomaly. Only a region that also
			// carries a magic-byte / embedded-payload / archive-structure signal
			// is escalated to malware. See plan §1.1.
			for _, r := range res.Regions {
				if r.FusedSeverity <= 0.6 {
					continue
				}
				if regionHasCorroboratingSignal(r) {
					analysis.Matches = append(analysis.Matches, newMatchWithScore(
						types.CategoryMalware, analysis.Path, 1,
						"Embedded Threat", strings.Join(r.DominantSignals, ", "), r.FusedSeverity*10, r.FusedSeverity > 0.8,
					))
				} else if !entropyExpected {
					// Entropy-only signal on a resource file whose format is NOT
					// compressed-by-design: informational.
					analysis.Matches = append(analysis.Matches, newMatchWithScore(
						types.CategoryMediaAnomaly, analysis.Path, 1,
						"High-Entropy Segment", strings.Join(r.DominantSignals, ", "), 2.0, false,
					))
				}
			}
		}
	}

	if len(analysis.Matches) > 0 || len(analysis.DecisionPoints) > 0 ||
		(analysis.IsAppCode && analysis.SuspiciousScore > p.suspiciousScoreThreshold()) {
		analysis.Hash = sha256Short(content)
	}

	return analysis
}

func shouldScanContent(fileType types.FileType, content []byte) bool {
	switch fileType {
	case types.FileTypeMedia, types.FileTypeArchive, types.FileTypeSignature:
		return false
	case types.FileTypeResource:
		return isLikelyTextContent(content)
	default:
		return true
	}
}

func shouldIndexLines(fileType types.FileType, content []byte) bool {
	switch fileType {
	case types.FileTypeSmali, types.FileTypeXML, types.FileTypeJSON,
		types.FileTypeProperties, types.FileTypeText, types.FileTypePatch:
		return true
	case types.FileTypeUnknown, types.FileTypeCache:
		return isLikelyTextContent(content)
	default:
		return false
	}
}

// regionHasCorroboratingSignal reports whether a high-severity media region
// carries evidence BEYOND raw entropy. A magic-byte signature, an embedded
// suspicious payload, or valid archive/APK structure inside a resource file is
// a genuine second signal; high entropy on its own is normal for compressed
// images and must not by itself escalate to malware. See plan §1.1.
func regionHasCorroboratingSignal(r media.Region) bool {
	for _, s := range r.Signals {
		switch s.Type {
		case media.SignalPayload, media.SignalZIPEOCD, media.SignalAPKStruct:
			return true
		case media.SignalMagic:
			// A magic signature is ONLY suspicious if it is an executable/archive format
			// (DEX, ELF, ZIP, EXE, JAR, APK) embedded inside a media resource, NOT if it
			// is just the normal image/audio format itself (PNG, JPEG, WEBP, GIF, OGG, WAV).
			val := strings.ToLower(s.Value)
			if val == "dex" || val == "elf" || val == "zip" || val == "exe" || val == "jar" || val == "apk" {
				return true
			}
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// COLLECT RESULT — thread-safe сбор результатов
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) collectResult(analysis *types.FileAnalysis) {
	p.stats.AnalysisUnits.Add(1)
	p.result.FilesByType[analysis.Type]++
	if analysis.IsAppCode {
		p.result.Stats.AppCodeFiles++
	}
	// Precision gate: drop proven false-positive matches (substring hits,
	// i18n prose, uncorroborated security keywords) BEFORE they reach
	// counters, reports and the GNN dataset. See pkg/internal/precisiongate.
	if suppressed := gateFileMatches(analysis); suppressed > 0 {
		logger.Debug("Precision gate suppressed matches",
			"file", analysis.Path, "count", suppressed)
	}
	// Recovered plaintext is a finding in its own right: something in this file
	// was deliberately hidden. Without this clause the file is dropped here and
	// the recovery never reaches the report.
	hasFindings := len(analysis.Matches) > 0 ||
		len(analysis.DecisionPoints) > 0 ||
		(analysis.Deobfuscation != nil && len(analysis.Deobfuscation.Methods) > 0) ||
		len(analysis.RecoveredStrings) > 0 ||
		len(analysis.RecoveredArtifacts) > 0 ||
		(analysis.IsAppCode && analysis.SuspiciousScore > p.suspiciousScoreThreshold())

	if !hasFindings {
		return
	}
	p.stats.FindingsBearing.Add(1)

	// 🆕 v8.3.0 - Применяем user feedback
	if p.userFeedback != nil {
		// Собираем все keywords из matches
		keywords := make([]string, 0, len(analysis.Matches))
		for _, m := range analysis.Matches {
			keywords = append(keywords, m.Pattern)
		}

		// Проверяем нужно ли отфильтровать как noise
		if p.userFeedback.ShouldFilterOut(analysis.Path, keywords) {
			// Файл помечен как noise - пропускаем
			return
		}

		// Проверяем нужно ли повысить важность
		if p.userFeedback.ShouldBoost(analysis.Path, keywords) {
			// Повышаем importance на 20%
			analysis.Importance = int(float64(analysis.Importance) * 1.2)

			// Помечаем все matches как critical
			for i := range analysis.Matches {
				analysis.Matches[i].IsCritical = true
			}
		}
	}

	// Protection categories describe the app protecting *itself* (anti-tamper,
	// anti-debug, anti-emulator, root checks). Inside a third-party library —
	// the vendored apksig signer checking isDebuggable of the APK it signs,
	// or androidx plumbing — they are not the app's protection stack and only
	// manufacture anti-analysis findings. Drop them from non-app code; the
	// match counters below have not run yet, so removal keeps stats honest.
	if !analysis.IsAppCode {
		kept := analysis.Matches[:0]
		for _, m := range analysis.Matches {
			switch m.Category {
			case types.CategoryIntegrityCheck, types.CategoryDebugDetection,
				types.CategoryEmulatorDetection, types.CategoryRootBypass,
				types.CategoryTamperDetection:
				continue
			}
			kept = append(kept, m)
		}
		analysis.Matches = kept
	}

	p.result.Files[analysis.Path] = analysis
	p.result.Stats.TotalMatches += len(analysis.Matches)
	p.stats.MatchesTotal.Add(int64(len(analysis.Matches)))

	for i := range analysis.Matches {
		match := &analysis.Matches[i]
		p.result.MatchesByCategory[match.Category]++

		// Respect per-match criticality (some detectors downgrade noisy hits).
		if match.IsCritical {
			p.result.Stats.CriticalMatches++
			p.stats.CriticalCount.Add(1)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI & XML PROCESSING
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) processSmali(analysis *types.FileAnalysis, content string) {
	t0sp := time.Now()
	smaliParser := parser.NewSmaliParser(content)
	class, err := smaliParser.Parse()
	p.stats.InternalTimings.SmaliParse.Record(time.Since(t0sp))
	if err != nil {
		analysis.ParseError = err.Error()
		return
	}

	class.IsAppCode = analysis.IsAppCode
	analysis.SmaliClass = class

	var shortMethodNames int
	totalMethods := len(class.Methods)

	lines := smaliParser.Lines()

	for i := range class.Methods {
		method := &class.Methods[i]
		if method.LineStart > 0 && method.LineEnd >= method.LineStart && method.LineEnd <= len(lines) {
			method.Body = lines[method.LineStart-1 : method.LineEnd]
		}

		dps := p.dpFinder.FindDecisionPoints(method, class.Name, analysis.Path)
		analysis.DecisionPoints = append(analysis.DecisionPoints, dps...)

		// 🆕 Run MethodAnalyzer on each method to classify roles
		if p.methodAnalyzer != nil && analysis.IsAppCode {
			var fm map[string]bool
			cacheable := p.contentCache != nil && len(method.Body) > 0
			if cacheable {
				if cached, ok := p.contentCache.GetMethodFeatures(class.Name, method.Name, method.Params, method.Body); ok {
					fm = make(map[string]bool, len(cached.FeatureIDs))
					for _, id := range cached.FeatureIDs {
						fm[id] = true
					}
					p.stats.InternalTimings.MethodFeatures.Hit()
				}
			}
			if fm == nil {
				t0mf := time.Now()
				ma := p.methodAnalyzer.AnalyzeFeatures(method, class)
				p.stats.InternalTimings.MethodFeatures.Record(time.Since(t0mf))
				p.stats.InternalTimings.MethodFeatures.Miss()
				fm = ma.FeatureMap
				if cacheable {
					ids := make([]string, 0, len(fm))
					for id, enabled := range fm {
						if enabled {
							ids = append(ids, id)
						}
					}
					sort.Strings(ids)
					p.contentCache.PutMethodFeatures(class.Name, method.Name, method.Params, method.Body, &contentcache.CachedFeatures{
						FeatureIDs:    ids,
						WeightedScore: ma.WeightedScore,
						RiskLevel:     int(ma.RiskLevel),
					})
				}
			}

			// Checker: returns boolean + has conditions + naming suggests check
			if fm["returns_boolean"] && fm["has_conditions"] &&
				(fm["name_contains_license"] || fm["name_contains_check"] ||
					fm["name_contains_validate"] || fm["name_contains_verify"]) {
				analysis.HasCheckerRole = true
			}

			// Enforcer: calls system_exit or finish
			if fm["calls_system_exit"] || fm["calls_finish_activity"] {
				analysis.HasEnforcerRole = true
			}

			// Handler: callback-like naming or billing/license API calls
			if fm["calls_billing_api"] || fm["calls_license_api"] {
				analysis.HasHandlerRole = true
			}
		}

		// Obfuscation density calculation
		if method.Name != "<init>" && method.Name != "<clinit>" && method.Name != "toString" && method.Name != "hashCode" && method.Name != "equals" {
			if len(method.Name) <= 2 {
				shortMethodNames++
			}
		}
	}

	if totalMethods > 0 {
		analysis.ObfuscationDensity = float64(shortMethodNames) / float64(totalMethods)
	}
	if p.dataFlow != nil {
		p.dataFlow.AddClass(analysis.Path, class)
	}

	// Suspicious methods scoring
	for i := range class.Methods {
		if score := class.Methods[i].SuspicionScore; score >= 2 {
			analysis.SuspiciousScore += float64(score)
		}
	}

	// Call graph
	if p.config.EnableCallGraph && analysis.IsAppCode {
		for i := range class.Methods {
			p.cgBuilder.AddMethod(class.Name, &class.Methods[i], analysis.Path)
		}
		p.typedCGBuilder.AddClass(dexiradapters.FromSmaliClassLines(class, lines))
	}

	// Deobfuscation runs here, during the scan, not in post-processing.
	//
	// It has to: collectResult drops any file that produced no findings, and a
	// class whose only interesting content is an encrypted literal produces
	// none by definition — the literal is encrypted, so no rule matches it.
	// Deobfuscating afterwards could therefore only ever look at files that
	// were already interesting, which is precisely the wrong half. Recovering
	// the plaintext here turns it into a finding and the file survives.
	if p.config.EnableDeobfuscation {
		p.deobfuscateClass(analysis, class)
		p.recoverStaticClassNetworkValues(analysis, class)
	}
}

// DetectorMetrics returns the lazily created per-detector accounting sink.
func (p *Pipeline) DetectorMetrics() *DetectorMetrics {
	p.detectorMetricsOnce.Do(func() {
		p.detectorMetrics = NewDetectorMetrics()
	})
	return p.detectorMetrics
}

// runOneDetector wraps one detector call with cost/yield accounting so the
// 35-detector chain stops being a single opaque 'detectors' counter.
func (p *Pipeline) runOneDetector(d FileDetector, dctx *FileDetectContext, analysis *types.FileAnalysis) {
	if independentFileDetector(d) {
		if result, ok := dctx.PrecomputedDetectors[d.Name()]; ok {
			analysis.Matches = append(analysis.Matches, result.Matches...)
			p.DetectorMetrics().Record(d.Name(), len(result.Matches), result.DurationNs)
			return
		}
	}
	if _, independent := d.(*PiracyDetectorAdapter); independent && dctx.PrecomputedPiracy != nil {
		analysis.Matches = append(analysis.Matches, (*dctx.PrecomputedPiracy)...)
		p.DetectorMetrics().Record(d.Name(), len(*dctx.PrecomputedPiracy), dctx.PiracyDuration.Nanoseconds())
		return
	}
	before := len(analysis.Matches)
	t0 := time.Now()
	d.Detect(dctx, analysis)
	p.DetectorMetrics().Record(d.Name(), len(analysis.Matches)-before, time.Since(t0).Nanoseconds())
}

// runDetectors applies the detector chain to one content view.
func (p *Pipeline) runDetectors(dctx *FileDetectContext, analysis *types.FileAnalysis, job FileJob) {
	defer normalizeSubscriptionVocabulary(dctx, analysis)
	// Raw forensic data blobs (e.g. global-metadata.dat, save files) are admitted
	// as Unknown only for the dedicated data/ detectors; skip generic detectors on
	// them to avoid false positives from scanning binary content.
	forensicOnly := job.Type == types.FileTypeUnknown && isForensicDataFile(job.RelPath)
	idx := p.getDetectorIndex()
	from := len(analysis.Matches)

	// 1. Fast path: detectors pre-indexed by FileType
	if int(job.Type) < len(idx.byType) {
		for _, detector := range idx.byType[job.Type] {
			p.runOneDetector(detector, dctx, analysis)
		}
	}

	// 2. Path-sensitive detectors (e.g. AndroidManifest.xml, res/values/...)
	for _, detector := range idx.pathSensitive {
		if selective, ok := detector.(FileTypeAwareDetector); ok {
			if selective.SupportsFile(job.Type, job.RelPath) {
				p.runOneDetector(detector, dctx, analysis)
			}
		}
	}

	// 3. Generic detectors (do not implement FileTypeAwareDetector)
	if !forensicOnly {
		for _, detector := range idx.generic {
			p.runOneDetector(detector, dctx, analysis)
		}
	}

	// 4. Metadata enrichment for smali findings (audit P2-13 / E1).
	enrichSmaliMatchMetadata(dctx, analysis, from)
}

// enrichSmaliMatchMetadata fills the provenance fields that byte-pattern
// detectors cannot know — the enclosing method, the class, and an honest
// default confidence — on every finding the detector chain produced for a
// smali file. AST-based detectors set these themselves and are left intact.
func enrichSmaliMatchMetadata(dctx *FileDetectContext, analysis *types.FileAnalysis, from int) {
	if dctx == nil || dctx.FileType != types.FileTypeSmali {
		return
	}
	class := dctx.Class
	for i := from; i < len(analysis.Matches); i++ {
		m := &analysis.Matches[i]
		if class != nil {
			if m.ClassName == "" {
				m.ClassName = class.Name
			}
			if m.MethodName == "" && m.Line > 0 {
				m.MethodName = methodAtLine(class, m.Line)
			}
		}
		if m.Confidence == "" {
			// Pattern-level evidence is never "high"; unresolved-operand and
			// critical findings sit one notch above plain substring hits.
			if m.EvidenceType == "smali_ast_dataflow" || m.IsCritical {
				m.Confidence = "medium"
			} else {
				m.Confidence = "low"
			}
		}
	}
}

// methodAtLine returns the name of the method whose body spans `line`.
func methodAtLine(class *types.SmaliClass, line int) string {
	for j := range class.Methods {
		method := &class.Methods[j]
		if method.LineStart > 0 && line >= method.LineStart && line <= method.LineEnd {
			return method.Name
		}
	}
	return ""
}

// rescanRecoveredContent runs the full detection chain — pattern matcher and
// detectors — over plaintext recovered from encrypted literals.
//
// Both halves are needed. The matcher carries the signature rules, but URLs,
// endpoints and several other high-value signals are produced by detectors, so
// feeding the matcher alone left a decrypted C2 endpoint undetected.
func (p *Pipeline) rescanRecoveredContent(ctx context.Context, analysis *types.FileAnalysis, job FileJob) {
	if len(analysis.RecoveredStrings) == 0 {
		return
	}
	// Present the plaintext as smali const-string lines: rules and detectors
	// are written against code, and a bare list of strings matches far less.
	var sb strings.Builder
	for _, s := range analysis.RecoveredStrings {
		sb.WriteString(`    const-string v0, "`)
		sb.WriteString(s)
		sb.WriteString("\"\n")
	}
	content := sb.String()
	lower := strings.ToLower(content)

	before := len(analysis.Matches)
	if p.matcher != nil {
		analysis.Matches = append(analysis.Matches,
			p.matcher.MatchContentWithFilterLower(content, lower, job.RelPath, analysis.IsAppCode)...)
	}
	p.runDetectors(&FileDetectContext{
		Ctx:          ctx,
		Path:         job.RelPath,
		Content:      []byte(content),
		ContentLower: []byte(lower),
		IsAppCode:    analysis.IsAppCode,
		FileType:     job.Type,
		Job:          job,
	}, analysis, job)

	// Mark provenance so a reviewer can tell a decrypted hit from one that was
	// sitting in the file in cleartext.
	for i := before; i < len(analysis.Matches); i++ {
		analysis.Matches[i].ResolvedContext = "decrypted string"
	}
	p.dispatchRecoveredArtifacts(ctx, analysis, job)
}

// deobfuscateClass analyses every method of a parsed class and records what the
// deobfuscation engine recovered on the file.
func (p *Pipeline) deobfuscateClass(analysis *types.FileAnalysis, class *types.SmaliClass) {
	opts := deobfuscator.Options{
		EnableCFF:       p.config.DeobfuscationOptions.EnableCFF,
		EnableOpaque:    p.config.DeobfuscationOptions.EnableOpaque,
		EnableDeadCode:  p.config.DeobfuscationOptions.EnableDeadCode,
		EnableStringDec: p.config.DeobfuscationOptions.EnableStringDec,
	}
	engine := deobfuscator.NewEngine(opts)
	optionKey := fmt.Sprintf("cff=%t;opaque=%t;dead=%t;strings=%t",
		opts.EnableCFF, opts.EnableOpaque, opts.EnableDeadCode, opts.EnableStringDec)

	// The CFG is built here, per method, from the raw body. types.FileAnalysis
	// carries a CFG field, but nothing in the tree ever assigns it, so every
	// consumer that filtered on it silently processed zero methods.
	builder := cfg.NewCFGBuilder()
	summary := &types.DeobfuscationResult{}
	var recovered []string

	// Sized once, ahead of the loop. This used to be re-tested on every method
	// and, on the first iteration, allocated a fresh slice that discarded any
	// graph a previous class had already stored for this file.
	if len(analysis.MethodCFGs) < len(class.Methods) {
		analysis.MethodCFGs = make([]*cfg.ControlFlowGraph, len(class.Methods))
	}

	for mi := range class.Methods {
		m := &class.Methods[mi]

		// ── Build CFG for method & retain in analysis ─────────────────────
		//
		// This runs before the deobfuscation cache lookup below and must keep
		// doing so: MethodCFGs is an output in its own right, consumed by the
		// GNN runner, so a cache hit may skip engine.Analyze() but not the
		// graph itself.
		t0cfg := time.Now()
		graph := buildMethodCFG(builder, class.Name, m)
		p.stats.InternalTimings.CFGBuild.Record(time.Since(t0cfg))
		analysis.MethodCFGs[mi] = graph

		// ── Deobfuscation content-cache check ─────────────────────────────
		// The versioned key includes method identity and every engine option.
		// A hit skips the engine, but preserves the same report and CFG.
		if p.contentCache != nil && len(m.Body) > 0 {
			if cached, ok := p.contentCache.GetMethodDeobf(class.Name, m.Name, m.Params+"->"+m.ReturnType, optionKey, m.Body); ok {
				p.stats.InternalTimings.Deobfuscation.Hit()
				recovered = append(recovered, cached.DeobfuscatedBody...)
				summary.CFFFDetected = summary.CFFFDetected || cached.CFFFDetected
				summary.OpaquePredicates += cached.OpaqueRemoved
				summary.DeadCodeNodes += cached.DeadCodeRemoved
				if cached.CFFFDetected || cached.OpaqueRemoved > 0 || cached.DeadCodeRemoved > 0 || len(cached.DeobfuscatedBody) > 0 {
					summary.Methods = append(summary.Methods, types.DeobfMethod{
						MethodName: m.Name,
						ClassName:  class.Name,
						Findings:   append([]string(nil), cached.Findings...),
					})
				}
				continue
			}
			p.stats.InternalTimings.Deobfuscation.Miss()
		}

		if graph == nil {
			continue
		}
		t0deobf := time.Now()
		res := engine.Analyze(graph)
		p.stats.InternalTimings.Deobfuscation.Record(time.Since(t0deobf))
		if !res.IsObfuscated() {
			// Store the negative result so a second pass skips the engine.
			if p.contentCache != nil && len(m.Body) > 0 {
				p.contentCache.PutMethodDeobf(class.Name, m.Name, m.Params+"->"+m.ReturnType, optionKey, m.Body, &contentcache.CachedDeobfResult{
					DeobfuscatedBody: nil,
					Confidence:       0,
				})
			}
			continue
		}

		// Obfuscation detected — collect findings.
		var methodRecovered []string
		var findings []string
		if res.CFFFDetected {
			summary.CFFFDetected = true
			findings = append(findings, "control-flow flattening")
		}
		if res.OpaquePredicatesFound > 0 {
			summary.OpaquePredicates += res.OpaquePredicatesFound
			findings = append(findings, fmt.Sprintf("%d opaque predicate(s)", res.OpaquePredicatesFound))
		}
		if res.DeadNodesFound > 0 {
			summary.DeadCodeNodes += res.DeadNodesFound
			findings = append(findings, fmt.Sprintf("%d unreachable block(s)", res.DeadNodesFound))
		}
		for _, s := range res.RecoveredStrings {
			if s.DecryptedForm == "" {
				continue
			}
			methodRecovered = append(methodRecovered, s.DecryptedForm)
			recovered = append(recovered, s.DecryptedForm)
			findings = append(findings, fmt.Sprintf("decrypted %q via %s", s.DecryptedForm, s.Transform))
		}
		summary.Methods = append(summary.Methods, types.DeobfMethod{
			MethodName: m.Name,
			ClassName:  class.Name,
			Findings:   findings,
		})

		// ── Store result in cache ─────────────────────────────────────────
		if p.contentCache != nil && len(m.Body) > 0 {
			confidence := 0.0
			if len(findings) > 0 {
				confidence = float64(len(methodRecovered)+res.OpaquePredicatesFound+res.DeadNodesFound) /
					float64(len(findings)+1)
				if confidence > 1.0 {
					confidence = 1.0
				}
			}
			p.contentCache.PutMethodDeobf(class.Name, m.Name, m.Params+"->"+m.ReturnType, optionKey, m.Body, &contentcache.CachedDeobfResult{
				DeobfuscatedBody: append([]string(nil), methodRecovered...),
				CFFFDetected:     res.CFFFDetected,
				Findings:         append([]string(nil), findings...),
				OpaqueRemoved:    res.OpaquePredicatesFound,
				DeadCodeRemoved:  res.DeadNodesFound,
				Confidence:       confidence,
			})
		}
	}

	if len(summary.Methods) == 0 {
		return
	}
	analysis.RecoveredStrings = dedupeStrings(recovered)
	summary.RecoveredStrings = len(analysis.RecoveredStrings)
	analysis.Deobfuscation = summary
}

const maxHyperionJournalEntriesPerMethod = 64

func (p *Pipeline) applyHyperionMethods(ctx context.Context, analysis *types.FileAnalysis, hyperion *apkloader.DeobfuscationPipeline, methods []apkloader.OwnedDEXMethod) {
	p.applyHyperionMethodsWithResolver(ctx, analysis, hyperion, methods, nil)
}

func (p *Pipeline) applyHyperionMethodsWithResolver(ctx context.Context, analysis *types.FileAnalysis, hyperion *apkloader.DeobfuscationPipeline, methods []apkloader.OwnedDEXMethod, resolver *apkloader.OwnedMethodResolver) {
	p.applyHyperionMethodsWithEnvironment(ctx, analysis, hyperion, methods, resolver, nil)
}

func (p *Pipeline) applyHyperionMethodsWithEnvironment(ctx context.Context, analysis *types.FileAnalysis, hyperion *apkloader.DeobfuscationPipeline, methods []apkloader.OwnedDEXMethod, resolver *apkloader.OwnedMethodResolver, statics *apkloader.OwnedStaticResolver) {
	if analysis == nil || hyperion == nil || len(methods) == 0 {
		return
	}
	if analysis.Deobfuscation == nil {
		analysis.Deobfuscation = &types.DeobfuscationResult{}
	}
	summary := analysis.Deobfuscation
	for _, method := range methods {
		if err := ctx.Err(); err != nil {
			return
		}
		transformed, err := hyperion.ProcessOwnedMethodWithEnvironment(ctx, method, resolver, statics)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Debug("Hyperion owned method skipped", "class", method.ClassName, "method", method.MethodName, "err", err)
			continue
		}
		summary.MethodsConsidered++
		metrics := transformed.Metrics
		callProofs := make([]types.DeobfCallProof, 0, len(transformed.Emulation.CallProofs))
		for _, proof := range transformed.Emulation.CallProofs {
			callProofs = append(callProofs, types.DeobfCallProof{Caller: proof.Caller, Callee: proof.Callee, Offset: proof.Offset, Depth: proof.Depth, Digest: proof.Digest, ArgumentSummary: append([]string(nil), proof.ArgumentSummary...), Status: proof.Status, Reason: proof.Reason, CacheHit: proof.CacheHit})
		}
		staticProofs := make([]types.DeobfStaticProof, 0, len(transformed.Emulation.StaticProofs))
		for _, proof := range transformed.Emulation.StaticProofs {
			staticProofs = append(staticProofs, types.DeobfStaticProof{ClassName: proof.ClassName, Field: proof.Field, Operation: proof.Operation, Offset: proof.Offset, State: proof.State, Reason: proof.Reason})
		}
		methodResult := types.DeobfMethod{
			ClassName: method.ClassName, MethodName: method.MethodName,
			CandidateScore:   method.CandidateScore,
			CandidateReasons: append([]string(nil), method.CandidateReasons...),
			Transformed:      transformed.Transformed,
			Emulation: &types.DeobfEmulation{
				Status: string(transformed.Emulation.Status), StopReason: transformed.Emulation.StopReason,
				Steps: transformed.Emulation.Steps, Branches: transformed.Emulation.Branches,
				Allocations:  transformed.Emulation.Allocations,
				CallProofs:   callProofs,
				StaticProofs: staticProofs,
				CallMetrics: types.DeobfCallMetrics{
					Attempts: transformed.Emulation.CallMetrics.Attempts, Completed: transformed.Emulation.CallMetrics.Completed,
					CacheHits: transformed.Emulation.CallMetrics.CacheHits, Recursions: transformed.Emulation.CallMetrics.Recursions,
					Impure: transformed.Emulation.CallMetrics.Impure, Unresolved: transformed.Emulation.CallMetrics.Unresolved,
					Budgeted: transformed.Emulation.CallMetrics.Budgeted,
				},
				Trace:           append([]string(nil), transformed.Emulation.Trace...),
				TraceTruncated:  transformed.Emulation.TraceTruncated,
				ProofsTruncated: transformed.Emulation.ProofsTruncated,
			},
			Metrics: &types.DeobfMetrics{
				BlocksBefore: metrics.BlocksBefore, BlocksAfter: metrics.BlocksAfter,
				EdgesBefore: metrics.EdgesBefore, EdgesAfter: metrics.EdgesAfter,
				InstructionsBefore: metrics.InsnsBefore, InstructionsAfter: metrics.InsnsAfter,
				FoldedConstants: metrics.FoldedConstants, FoldedBranches: metrics.FoldedBranches,
				RemovedBlocks: metrics.RemovedBlocks, ProofsAccepted: metrics.ProofsAccepted,
			},
		}
		summary.EmulatorAttempts++
		switch transformed.Emulation.Status {
		case apkloader.DalvikEmulationRecovered:
			summary.EmulatorRecoveries += len(transformed.RecoveredValues)
		case apkloader.DalvikEmulationAbstained:
			summary.EmulatorAbstentions++
		case apkloader.DalvikEmulationBudgetExhausted:
			summary.EmulatorBudgets++
		}
		for _, recovered := range transformed.RecoveredValues {
			analysis.RecoveredStrings = append(analysis.RecoveredStrings, recovered.Value)
			methodResult.RecoveredValues = append(methodResult.RecoveredValues, types.DeobfRecoveredValue{
				Value: recovered.Value, Offset: recovered.Offset, Source: recovered.Source,
				Proof: recovered.Proof, Operations: append([]string(nil), recovered.Operations...),
			})
		}
		analysis.RecoveredStrings = dedupeStrings(analysis.RecoveredStrings)
		summary.RecoveredStrings = len(analysis.RecoveredStrings)
		journal := transformed.Journal
		if len(journal) > maxHyperionJournalEntriesPerMethod {
			journal = journal[:maxHyperionJournalEntriesPerMethod]
			methodResult.JournalTruncated = true
			summary.JournalTruncated = true
		}
		for _, entry := range journal {
			methodResult.Journal = append(methodResult.Journal, types.DeobfTransform{
				Pass: entry.Pass, BlockID: entry.BlockID, InsnIndex: entry.InsnIndex,
				Proof: entry.Proof, Confidence: entry.Confidence,
			})
		}
		summary.Methods = append(summary.Methods, methodResult)
		summary.ProofsAccepted += metrics.ProofsAccepted
		summary.FoldedConstants += metrics.FoldedConstants
		summary.FoldedBranches += metrics.FoldedBranches
		summary.DeadCodeNodes += metrics.RemovedBlocks
		summary.BlocksBefore += metrics.BlocksBefore
		summary.BlocksAfter += metrics.BlocksAfter
		summary.EdgesBefore += metrics.EdgesBefore
		summary.EdgesAfter += metrics.EdgesAfter
		summary.InstructionsBefore += metrics.InsnsBefore
		summary.InstructionsAfter += metrics.InsnsAfter
		if transformed.Transformed {
			summary.MethodsTransformed++
		}
	}
}

func (p *Pipeline) processXML(analysis *types.FileAnalysis, content, contentLower []byte) {
	// Suspicious keywords
	suspicious := findXMLSuspicious(contentLower)
	if len(suspicious) > 0 {
		analysis.XMLData = &types.XMLAnalysis{Suspicious: suspicious}
	}
	if isAndroidManifestPath(analysis.RelPath) || isAndroidManifestPath(analysis.Path) {
		if analysis.XMLData == nil {
			analysis.XMLData = &types.XMLAnalysis{}
		}
		const maxManifestContext = 128 << 10
		if len(content) <= maxManifestContext {
			analysis.XMLData.ManifestSource = string(content)
		} else {
			analysis.XMLData.ManifestSourceTruncated = true
		}
	}

	// Ad patterns in XML
	detectXMLAds(analysis, content)
	detectXMLAnalytics(analysis, contentLower)
}

// ═══════════════════════════════════════════════════════════════════════════════
// XML HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

var xmlSuspiciousKeywords = [][]byte{
	[]byte("license"), []byte("billing"), []byte("purchase"), []byte("premium"),
	[]byte("pro"), []byte("subscription"), []byte("api_key"), []byte("secret"),
	[]byte("admob"), []byte("facebook_ads"), []byte("unity_ads"),
}

func findXMLSuspicious(contentLower []byte) []string {
	var result []string
	for _, kw := range xmlSuspiciousKeywords {
		if bytes.Contains(contentLower, kw) {
			result = append(result, string(kw))
		}
	}
	return result
}

var xmlAdPatterns = [][]byte{
	[]byte("com.google.android.gms.ads.AdView"),
	[]byte("com.google.android.gms.ads.AdManagerAdView"),
	[]byte("com.facebook.ads.AdView"),
	[]byte("ca-app-pub-"),
}

func detectXMLAds(analysis *types.FileAnalysis, content []byte) {
	for _, ptn := range xmlAdPatterns {
		if idx := bytes.Index(content, ptn); idx >= 0 {
			line := 0
			if analysis.LineOffsets != nil {
				line = analysis.LineOffsets.LineAt(idx)
			}
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryAdShow, analysis.Path, line,
				"XML Ad indicator",
				types.TruncateString(string(ptn), 100),
				false,
			))
		}
	}
}

var xmlAnalyticsPatterns = [][]byte{
	[]byte("firebase_analytics"),
	[]byte("appsflyer"),
	[]byte("crashlytics"),
}

func detectXMLAnalytics(analysis *types.FileAnalysis, contentLower []byte) {
	for _, ptn := range xmlAnalyticsPatterns {
		if idx := bytes.Index(contentLower, ptn); idx >= 0 {
			line := 0
			if analysis.LineOffsets != nil {
				line = analysis.LineOffsets.LineAt(idx)
			}
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryAnalytics, analysis.Path, line,
				"XML Analytics indicator", string(ptn), false,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOW-LEVEL HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func sha256Short(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:16])
}

// isCompressedMediaPath reports whether the file extension denotes a
// compressed-by-design media/font container, for which uniformly high
// entropy is normal and must never be reported as an anomaly on its own.
func isCompressedMediaPath(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".mp3", ".ogg", ".oga", ".opus", ".m4a", ".aac", ".png", ".jpg",
		".jpeg", ".webp", ".gif", ".mp4", ".webm", ".ico", ".woff", ".woff2":
		return true
	}
	return false
}
