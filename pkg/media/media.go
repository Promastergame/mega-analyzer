package media

import "time"

// AnalysisResult is the standard output of ForensicEngine.Analyze.
type AnalysisResult struct {
	FilePath       string         `json:"file_path"`
	Format         MediaType      `json:"format"`
	Classification Classification `json:"classification"`
	Regions        []Region       `json:"regions"`
	GlobalStats    GlobalStats    `json:"global_stats"`
	RiskScore      float64        `json:"risk_score"`

	// IOCs are indicators of compromise extracted from embedded or
	// obfuscated content (embedded executables, C2 URLs/IPs, .onion
	// addresses, crypto wallets, shell/download cradles, etc.). Populated
	// during analysis; nil when none were found.
	IOCs []IOC `json:"iocs,omitempty"`

	// Error is set when the file could not be read or analyzed. When it is
	// non-empty, the result must NOT be interpreted as a clean/safe verdict.
	Error string `json:"error,omitempty"`
}

// DeepAnalysis holds optional deep-scan results that are only populated
// when AnalysisContext.Depth == DepthDeep. Fields are nil/zero when not
// computed.
type DeepAnalysis struct {
	Heatmap      *EntropyHeatmap     `json:"heatmap,omitempty"`
	StegoSignals []StegoSignal       `json:"stego_signals,omitempty"`
	Timeline     *Timeline           `json:"timeline,omitempty"`
	Fingerprint  *EncoderFingerprint `json:"fingerprint,omitempty"`
	Watermarks   []WatermarkSignal   `json:"watermarks,omitempty"`
}

// ForensicEngine is the core forensic analysis orchestrator. It is
// intentionally stateless — all mutable state lives in the per-call
// AnalysisContext, so multiple goroutines can share one engine.
type ForensicEngine struct {
	detector   *Detector
	fusion     *FusionLayer
	classifier *Classifier
	scorer     *Scorer
}

func NewForensicEngine() *ForensicEngine {
	return &ForensicEngine{
		detector:   NewDetector(),
		fusion:     NewFusionLayer(),
		classifier: NewClassifier(),
		scorer:     NewScorer(),
	}
}

// Analyze performs a standard-depth forensic analysis of the given data.
// This is the backward-compatible entry point that uses DepthStandard.
func (e *ForensicEngine) Analyze(data []byte, filepath, filename string) AnalysisResult {
	return e.AnalyzeWithCtx(data, filepath, filename, DefaultContext())
}

// AnalyzeWithCtx performs a forensic analysis at the depth specified by ctx.
func (e *ForensicEngine) AnalyzeWithCtx(data []byte, filepath, filename string, ctx *AnalysisContext) AnalysisResult {
	if ctx == nil {
		ctx = DefaultContext()
	}
	if len(data) == 0 {
		ctx.log().Warn("pipeline", "Empty data passed to analyzer", "filepath", filepath)
		return AnalysisResult{FilePath: filepath}
	}

	log := ctx.log()
	start := time.Now()
	log.LogAnalysisStart(filepath, ctx.Depth, len(data))

	// ── Phase 1: Detection ────────────────────────────────────────────
	t := time.Now()
	ctx.reportProgress("detect", 0.0)
	signals, globalStats := e.detector.Detect(data)
	log.Debug("detect", "Detection complete",
		"signals_found", len(signals),
		"mean_entropy", globalStats.MeanEntropy,
		"peaks", globalStats.Peaks,
	)

	// Log individual signals at Trace level
	for _, sig := range signals {
		switch sig.Type {
		case SignalMagic:
			log.LogMagicDetection(MediaType(sig.Value), sig.Offset, sig.Confidence)
		case SignalHighEntropy:
			log.LogEntropyAnomaly(sig.Offset, sig.Length, sig.Metadata.EntropyScore, sig.Metadata.ZScore)
		case SignalPayload:
			log.LogPayloadDetection(sig.Value, sig.Offset, sig.Confidence, sig.Severity, sig.Metadata.Evidence)
		case SignalPrivacyLeak:
			log.LogPrivacyLeak(sig.Value, sig.Metadata.Evidence, sig.Offset)
		}
	}
	log.Trace("detect", "Phase complete", "duration_ms", time.Since(t).Milliseconds())

	if ctx.cancelled() {
		log.Warn("pipeline", "Analysis cancelled during detection", "filepath", filepath)
		return AnalysisResult{FilePath: filepath}
	}

	// ── Phase 2: Fusion ──────────────────────────────────────────────
	t = time.Now()
	ctx.reportProgress("fuse", 0.2)
	regions := e.fusion.Fuse(signals)
	log.Debug("fuse", "Signal fusion complete",
		"regions", len(regions),
		"total_signals", len(signals),
	)
	for i, r := range regions {
		log.Trace("fuse", "Region details",
			"region", i,
			"start", r.StartOffset,
			"end", r.EndOffset,
			"signals", len(r.Signals),
			"fused_severity", r.FusedSeverity,
			"fused_confidence", r.FusedConfidence,
			"dominant", r.DominantSignals,
		)
	}
	log.Trace("fuse", "Phase complete", "duration_ms", time.Since(t).Milliseconds())

	// ── Phase 3: Classification ───────────────────────────────────────
	t = time.Now()
	ctx.reportProgress("classify", 0.3)
	class := e.classifier.Classify(globalStats, regions, filename)
	log.Debug("classify", "Classification complete",
		"primary_format", class.PrimaryFormat,
		"confidence", class.Confidence,
		"is_polyglot", class.IsPolyglot,
		"hidden_formats", class.HiddenFormats,
	)

	if class.IsPolyglot {
		log.LogPolyglot(class.PrimaryFormat, class.HiddenFormats, class.IsPolyglot)
	}
	log.Trace("classify", "Phase complete", "duration_ms", time.Since(t).Milliseconds())

	if ctx.cancelled() {
		log.Warn("pipeline", "Analysis cancelled during classification", "filepath", filepath)
		return AnalysisResult{FilePath: filepath}
	}

	// ── Phase 4: Metadata extraction ──────────────────────────────────
	if ctx.Depth >= DepthStandard {
		t = time.Now()
		switch class.PrimaryFormat {
		case TypeJPEG, TypePNG, TypeWEBP, TypeICO, TypeSVG,
			TypeGIF, TypeBMP, TypeTIFF, TypeDNG, TypeRAW,
			TypeHEIC, TypeAVIF, TypePSD, TypeJXL:
			meta := extractMediaMetadataFull(data, class.PrimaryFormat, filename)
			for k, v := range meta.Fields {
				class.RecoveredData[k] = v
			}
			class.MediaExtra = &meta
			log.LogMetadataExtraction(class.PrimaryFormat, len(meta.Fields))
			if meta.TrailingData != nil {
				log.Warn("metadata",
					"Trailing data detected after logical EOF",
					"offset", meta.TrailingData.Offset,
					"size", meta.TrailingData.Size,
					"detected_format", meta.TrailingData.DetectedFormat,
				)
			}
		}
		log.Trace("metadata", "Phase complete", "duration_ms", time.Since(t).Milliseconds())
	}

	// ── Phase 5: Scoring ─────────────────────────────────────────────
	t = time.Now()
	ctx.reportProgress("score", 0.5)
	// Annotate regions with human-readable reasons and neutralize the
	// benign "own signature + normal compression entropy" pattern so a
	// clean PNG/JPEG no longer scores ~69/100 just for being compressed.
	regions = e.scorer.AnnotateRegions(regions, class)
	score, rb := e.scorer.ScoreWithBreakdown(class, regions, globalStats)
	log.LogRiskScore(score, rb.PolyglotRisk, rb.RegionRisk, rb.EntropyRisk)
	log.Trace("score", "Phase complete", "duration_ms", time.Since(t).Milliseconds())

	// ── Phase 6: IOC extraction & threat enrichment ─────────────────
	// Extract actionable indicators of compromise (embedded executables,
	// C2 URLs/IPs, .onion addresses, crypto wallets, shell/download cradles)
	// from embedded and base64-obfuscated content, then fold an IOC-derived
	// risk into the score. Folding uses the shared model and can only raise
	// the score, never lower it.
	t = time.Now()
	ctx.reportProgress("ioc", 0.6)
	iocs := ExtractIOCs(data, regions)
	if len(iocs) > 0 {
		iocScore := IOCRiskScore(iocs)
		score = combinePercentages(score, iocScore)
		log.Debug("ioc", "IOC extraction complete",
			"iocs_found", len(iocs),
			"ioc_risk", iocScore,
			"adjusted_score", score,
		)
	}
	log.Trace("ioc", "Phase complete", "duration_ms", time.Since(t).Milliseconds())

	result := AnalysisResult{
		FilePath:       filepath,
		Format:         class.PrimaryFormat,
		Classification: class,
		Regions:        regions,
		GlobalStats:    globalStats,
		RiskScore:      score,
		IOCs:           iocs,
	}

	log.LogAnalysisComplete(filepath, class.PrimaryFormat, score, time.Since(start))
	ctx.reportProgress("done", 1.0)
	return result
}

// AnalyzeDeep performs a full deep forensic analysis including entropy
// heatmap, steganography detection, timeline, fingerprinting, and
// watermark detection. Returns both the standard result and the deep
// analysis output.
func (e *ForensicEngine) AnalyzeDeep(data []byte, filepath, filename string) (AnalysisResult, *DeepAnalysis) {
	ctx := &AnalysisContext{Depth: DepthDeep, ForensicLog: SilentLogger()}
	result := e.AnalyzeWithCtx(data, filepath, filename, ctx)

	if len(data) == 0 {
		return result, nil
	}

	log := ctx.log()
	deep := &DeepAnalysis{}

	// Entropy heatmap
	t := time.Now()
	ctx.reportProgress("heatmap", 0.6)
	deep.Heatmap = BuildEntropyHeatmap(data, 256)
	if deep.Heatmap != nil {
		anomalies := deep.Heatmap.Anomalies(3.0)
		log.Debug("heatmap", "Entropy heatmap built",
			"width", deep.Heatmap.Width,
			"height", deep.Heatmap.Height,
			"anomalies", len(anomalies),
		)
	}

	// Steganography detection
	t = time.Now()
	ctx.reportProgress("stego", 0.7)
	deep.StegoSignals = DetectSteganography(data, result.Format)
	for _, sig := range deep.StegoSignals {
		log.LogStegoDetection(sig.Method, sig.Confidence, sig.Evidence)
	}
	log.Debug("stego", "Steganography analysis complete",
		"signals_found", len(deep.StegoSignals),
		"duration_ms", time.Since(t).Milliseconds(),
	)

	// Timeline
	if result.Classification.MediaExtra != nil {
		t = time.Now()
		ctx.reportProgress("timeline", 0.8)
		deep.Timeline = BuildTimeline(result.Classification.MediaExtra)
		if deep.Timeline != nil {
			for _, a := range deep.Timeline.Anomalies {
				log.LogTimelineAnomaly(a.Type, a.Description)
			}
			log.Debug("timeline", "Timeline built",
				"entries", len(deep.Timeline.Entries),
				"anomalies", len(deep.Timeline.Anomalies),
				"duration_ms", time.Since(t).Milliseconds(),
			)
		}
	}

	// Encoder fingerprinting
	t = time.Now()
	ctx.reportProgress("fingerprint", 0.9)
	deep.Fingerprint = FingerprintFile(data, result.Format)
	// deep.Fingerprint is nil for any format other than JPEG/PNG (and for
	// unparseable inputs). Guard EVERY access — including the debug log's
	// argument evaluation — so non-JPEG/PNG files never trigger a nil
	// pointer dereference here.
	if deep.Fingerprint != nil {
		if deep.Fingerprint.Confidence > 0.3 {
			log.LogFingerprint(deep.Fingerprint.Encoder, deep.Fingerprint.Confidence, deep.Fingerprint.Evidence)
		}
		log.Debug("fingerprint", "Fingerprinting complete",
			"encoder", deep.Fingerprint.Encoder,
			"confidence", deep.Fingerprint.Confidence,
			"duration_ms", time.Since(t).Milliseconds(),
		)
	} else {
		log.Debug("fingerprint", "Fingerprinting complete",
			"encoder", "unknown",
			"confidence", 0.0,
			"duration_ms", time.Since(t).Milliseconds(),
		)
	}

	// Watermark detection
	t = time.Now()
	ctx.reportProgress("watermarks", 0.95)
	deep.Watermarks = DetectWatermarks(data, result.Format)
	for _, wm := range deep.Watermarks {
		log.LogWatermarkDetection(wm.Type, wm.Confidence, wm.Evidence)
	}
	log.Debug("watermarks", "Watermark detection complete",
		"watermarks_found", len(deep.Watermarks),
		"duration_ms", time.Since(t).Milliseconds(),
	)

	ctx.reportProgress("done", 1.0)
	return result, deep
}
