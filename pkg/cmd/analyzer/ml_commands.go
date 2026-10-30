package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mega-analyzer/pkg/gamemode"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/training"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ML COMMAND RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

type MLRunner struct {
	opts    *CLIOptions
	history *ml.AnalysisHistory
	output  io.Writer
	errOut  io.Writer
}

func NewMLRunner(opts *CLIOptions) (*MLRunner, error) {
	historyPath, err := ml.DefaultHistoryPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get history path: %w", err)
	}

	history, err := ml.LoadHistory(historyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load history: %w", err)
	}

	return &MLRunner{
		opts:    opts,
		history: history,
		output:  os.Stdout,
		errOut:  os.Stderr,
	}, nil
}

// Run выполняет ML команду
func (r *MLRunner) Run() error {
	switch {
	case r.opts.MLExList:
		return r.listExperimentalModules()
	case r.opts.MLSuggest:
		return r.runSuggester()
	case r.opts.MLHistory:
		return r.showHistory()
	case r.opts.MLStats:
		return r.showStats()
	case r.opts.MLTrain || r.opts.MLTrainEnsemble:
		return r.runTrain()
	case r.opts.ShowFeedback:
		return r.showFeedback()
	case r.opts.PatternStats:
		return r.showPatternStats()
	case r.opts.ExportPatternStats != "":
		return r.exportPatternStats()
	case r.opts.FeedbackFile != "":
		return r.importFeedback()
	case r.opts.MLApply != "":
		return r.applyMLSuggestions()
	case r.opts.MarkRelevant != "":
		return r.markFeedback(r.opts.MarkRelevant, "relevant")
	case r.opts.MarkNoise != "":
		return r.markFeedback(r.opts.MarkNoise, "noise")
	default:
		return fmt.Errorf("no ML command specified")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRAIN — keyword relevance model from history.json
// ═══════════════════════════════════════════════════════════════════════════════

// runTrain learns a calibrated keyword-relevance model from the analyzer's own
// run history and persists it to ~/.analyzer/models/. Subsequent analyses pick
// it up automatically; if training fails or there is too little data, the
// existing heuristics remain in force.
func (r *MLRunner) runTrain() error {
	records := r.history.Snapshot()
	if len(records) == 0 {
		return r.showEmptyHistoryMessage()
	}

	if r.opts.MLTrain || !r.opts.MLTrainEnsemble {
		opts := training.DefaultTrainOptions()

		model, stats, err := training.Train(records, opts)
		if err != nil {
			// Still surface what we extracted so the user knows why.
			fmt.Fprintln(r.output)
			fmt.Fprintf(r.errOut, "  Training aborted: %v\n", err)
			fmt.Fprintf(r.output, "  Labels found: hard=%d heuristic=%d (pos=%d neg=%d) over %d unique keywords\n",
				stats.HardLabeled, stats.HeuristicLabeled, stats.Positives, stats.Negatives, stats.UniqueKeywords)
			fmt.Fprintln(r.output, "  Tip: mark findings with --mark-relevant / --mark-noise to add hard labels.")
			if !r.opts.MLTrainEnsemble {
				return err
			}
		} else {
			modelPath, err := training.DefaultModelPath()
			if err != nil {
				return err
			}
			if err := training.SaveModel(model, modelPath); err != nil {
				return fmt.Errorf("save model: %w", err)
			}

			fmt.Fprintln(r.output)
			fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
			fmt.Fprintln(r.output, "  ║        KEYWORD RELEVANCE — TRAINED       ║")
			fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
			fmt.Fprintln(r.output)
			fmt.Fprintf(r.output, "  Unique keywords : %d\n", stats.UniqueKeywords)
			fmt.Fprintf(r.output, "  Samples         : %d  (hard=%d, heuristic=%d)\n",
				model.SampleCount, stats.HardLabeled, stats.HeuristicLabeled)
			fmt.Fprintf(r.output, "  Class balance   : %d relevant / %d noise\n", stats.Positives, stats.Negatives)
			if model.CalibFitted {
				fmt.Fprintf(r.output, "  Calibration ECE : %s\n", training.ECESummary(true, model.ECE, model.ECESamples, model.ECEReliable, model.ECELow, model.ECEHigh))
				fmt.Fprintf(r.output, "  Splits/labels   : groups=%d group_split=%v coverage=%.2f pseudo_share=%.2f\n",
					model.Groups, model.GroupSplit, model.Coverage, model.PseudoFraction)
			} else {
				fmt.Fprintf(r.output, "  Calibration     : skipped (hold-out below %d samples)\n", training.MinCalibSamples)
			}
			fmt.Fprintf(r.output, "  Saved to        : %s\n", modelPath)
			fmt.Fprintln(r.output)
			fmt.Fprintln(r.output, "  The next analysis run will load this model automatically.")
			fmt.Fprintln(r.output)
		}
	}

	if r.opts.MLTrainEnsemble {
		eOpts := training.DefaultEnsembleTrainOptions()
		eModel, eStats, err := training.TrainEnsemble(records, eOpts)
		if err != nil {
			fmt.Fprintln(r.output)
			fmt.Fprintf(r.errOut, "  Ensemble training aborted: %v\n", err)
			fmt.Fprintf(r.output, "  Labels found: overrides=%d labeled=%d (pos=%d neg=%d)\n",
				eStats.TotalOverrides, eStats.LabeledSamples, eStats.Positives, eStats.Negatives)
			fmt.Fprintln(r.output, "  Tip: not enough labeled snapshots - use --mark-relevant/--mark-noise")
			return err
		}

		eModelPath, err := training.DefaultEnsembleModelPath()
		if err != nil {
			return err
		}
		if err := training.SaveEnsembleModel(eModel, eModelPath); err != nil {
			return fmt.Errorf("save ensemble model: %w", err)
		}

		fmt.Fprintln(r.output)
		fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
		fmt.Fprintln(r.output, "  ║          ENSEMBLE RISK — TRAINED         ║")
		fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
		fmt.Fprintln(r.output)
		fmt.Fprintf(r.output, "  Total overrides : %d\n", eStats.TotalOverrides)
		fmt.Fprintf(r.output, "  Labeled samples : %d\n", eModel.SampleCount)
		fmt.Fprintf(r.output, "  Class balance   : %d relevant / %d noise\n", eStats.Positives, eStats.Negatives)
		if eModel.CalibFitted {
			fmt.Fprintf(r.output, "  Calibration ECE : %s\n", training.ECESummary(true, eModel.ECE, eModel.ECESamples, eModel.ECEReliable, eModel.ECELow, eModel.ECEHigh))
			fmt.Fprintf(r.output, "  Splits          : groups=%d group_split=%v\n", eModel.Groups, eModel.GroupSplit)
		} else {
			fmt.Fprintf(r.output, "  Calibration     : skipped (hold-out below %d samples)\n", training.MinCalibSamples)
		}
		fmt.Fprintf(r.output, "  Saved to        : %s\n", eModelPath)
		fmt.Fprintln(r.output)
		fmt.Fprintln(r.output, "  The next patch analysis run will load this model automatically.")
		fmt.Fprintln(r.output)
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUGGESTER
// ═══════════════════════════════════════════════════════════════════════════════
func (r *MLRunner) runSuggester() error {
	if r.history.Len() == 0 {
		return r.showEmptyHistoryMessage()
	}

	// Создаём suggester с настройками из CLI
	cfg := ml.DefaultSuggesterConfig()
	cfg.ConfidenceThreshold = r.opts.MLConfidence
	if r.opts.MLMaxSuggestions > 0 {
		cfg.MaxDisplaySuggestions = r.opts.MLMaxSuggestions
	}

	// Получаем текущий ранг для персонализации
	rankSystem := gamemode.NewRankSystem()
	currentRank := rankSystem.GetCurrentRank("default")

	suggesterOpts := []func(*ml.MLSuggester){
		ml.WithSuggesterConfig(cfg),
		ml.WithOutput(r.output),
		ml.WithPersona("ML-chan", currentRank.ID),
	}
	// Trained relevance model (if present) refines keyword suggestions.
	if scorer, err := training.NewKeywordScorer(); err == nil && scorer.IsLoaded() {
		suggesterOpts = append(suggesterOpts, ml.WithRelevanceScorer(scorer))
		if !r.opts.Quiet && !r.opts.JSON {
			fmt.Fprintf(r.output, "  [ML] relevance model active: %s\n", scorer.ModelInfo())
		}
	}

	suggester := ml.NewMLSuggester(r.history, suggesterOpts...)

	// Если нужен экспорт в файл
	if r.opts.MLExport != "" {
		return r.exportSuggestions(suggester)
	}

	// Если JSON output
	if r.opts.JSON {
		return r.jsonSuggestions(suggester)
	}

	// Интерактивный вывод
	suggester.InteractiveSuggest()

	return nil
}

func (r *MLRunner) showEmptyHistoryMessage() error {
	if r.opts.JSON {
		return json.NewEncoder(r.output).Encode(map[string]interface{}{
			"error":   "no_history",
			"message": "No analysis history found. Run some analyses first.",
		})
	}

	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(r.output, "  ║           INTELLIGENCE REPORT            ║")
	fmt.Fprintln(r.output, "  ║            Adaptive Analysis             ║")
	fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  No analysis history found.")
	fmt.Fprintln(r.output, "  Run some analyses first to build learning data.")
	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  Example:")
	fmt.Fprintln(r.output, "    analyzer ./app.apk")
	fmt.Fprintln(r.output, "    analyzer ./another_app.apk")
	fmt.Fprintln(r.output, "    analyzer --suggest")
	fmt.Fprintln(r.output)

	return nil
}

func (r *MLRunner) exportSuggestions(suggester *ml.MLSuggester) error {
	result := suggester.Analyze()

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal suggestions: %w", err)
	}

	if err := os.WriteFile(r.opts.MLExport, data, 0644); err != nil {
		return fmt.Errorf("failed to write suggestions: %w", err)
	}

	if !r.opts.Quiet {
		fmt.Fprintf(r.errOut, "Exported %d suggestions to %s\n",
			len(result.Suggestions), r.opts.MLExport)
	}

	return nil
}

func (r *MLRunner) jsonSuggestions(suggester *ml.MLSuggester) error {
	result := suggester.Analyze()

	encoder := json.NewEncoder(r.output)
	encoder.SetIndent("", "  ")

	return encoder.Encode(result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// HISTORY
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MLRunner) showHistory() error {
	if r.opts.JSON {
		return r.jsonHistory()
	}

	records := r.history.LastN(20)

	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(r.output, "  ║           ANALYSIS HISTORY               ║")
	fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(r.output)

	if len(records) == 0 {
		fmt.Fprintln(r.output, "  No analysis history found.")
		fmt.Fprintln(r.output)
		return nil
	}

	fmt.Fprintf(r.output, "  Total records: %d (showing last %d)\n\n",
		r.history.Len(), len(records))

	fmt.Fprintln(r.output, "  ─────────────────────────────────────────────────────────────────")
	fmt.Fprintf(r.output, "  %-4s %-20s %-32s %s\n", "#", "Timestamp", "APK", "Findings")
	fmt.Fprintln(r.output, "  ─────────────────────────────────────────────────────────────────")

	for i, rec := range records {
		ts := rec.Timestamp.Format("2006-01-02 15:04")
		apkName := truncateString(rec.APKName, 30)
		findings := fmt.Sprintf("%d files, %d crit", rec.AnalyzedFiles, rec.CriticalCount)

		fmt.Fprintf(r.output, "  %-4d %-20s %-32s %s\n", i+1, ts, apkName, findings)
	}

	fmt.Fprintln(r.output, "  ─────────────────────────────────────────────────────────────────")
	fmt.Fprintln(r.output)

	return nil
}

func (r *MLRunner) jsonHistory() error {
	records := r.history.LastN(50)

	type historyEntry struct {
		Index         int       `json:"index"`
		Timestamp     time.Time `json:"timestamp"`
		APKName       string    `json:"apk_name"`
		Package       string    `json:"package"`
		AnalyzedFiles int       `json:"analyzed_files"`
		CriticalCount int       `json:"critical_count"`
		TotalMatches  int       `json:"total_matches"`
	}

	entries := make([]historyEntry, 0, len(records))
	for i, rec := range records {
		entries = append(entries, historyEntry{
			Index:         i + 1,
			Timestamp:     rec.Timestamp,
			APKName:       rec.APKName,
			Package:       rec.Package,
			AnalyzedFiles: rec.AnalyzedFiles,
			CriticalCount: rec.CriticalCount,
			TotalMatches:  rec.TotalMatches,
		})
	}

	encoder := json.NewEncoder(r.output)
	encoder.SetIndent("", "  ")

	return encoder.Encode(map[string]interface{}{
		"total":   r.history.Len(),
		"showing": len(entries),
		"entries": entries,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MLRunner) showStats() error {
	if r.opts.JSON {
		return r.jsonStats()
	}

	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(r.output, "  ║         AGGREGATED STATISTICS            ║")
	fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(r.output)

	if r.history.Len() == 0 {
		fmt.Fprintln(r.output, "  No analysis history found.")
		fmt.Fprintln(r.output)
		return nil
	}

	fmt.Fprintf(r.output, "  Total analyses: %d\n\n", r.history.Len())

	// Trained relevance model status.
	if scorer, err := training.NewKeywordScorer(); err == nil {
		fmt.Fprintf(r.output, "  Relevance model: %s\n\n", scorer.ModelInfo())
	}

	// Keyword stats
	keywords := r.history.AggregateKeywordStats()
	fmt.Fprintf(r.output, "  Keywords tracked: %d\n", len(keywords))

	// Top noisy
	noisy := r.history.TopNoisyKeywords(5)
	if len(noisy) > 0 {
		fmt.Fprintln(r.output)
		fmt.Fprintln(r.output, "  Top Noisy Keywords:")
		fmt.Fprintln(r.output, "  ───────────────────")
		for i, kw := range noisy {
			fmt.Fprintf(r.output, "  %d. %-20s noise: %.0f%%, triggered: %d\n",
				i+1, truncateString(kw.Keyword, 18), kw.NoiseRatio*100, kw.TotalTriggered)
		}
	}

	// Library stats
	libraries := r.history.AggregateLibraryStats()
	fmt.Fprintln(r.output)
	fmt.Fprintf(r.output, "  Libraries tracked: %d\n", len(libraries))

	// Always noise libraries
	alwaysNoise := r.history.AlwaysNoiseLibraries(2)
	if len(alwaysNoise) > 0 {
		fmt.Fprintln(r.output)
		fmt.Fprintln(r.output, "  Always-Noise Libraries (candidates for fast-path):")
		fmt.Fprintln(r.output, "  ──────────────────────────────────────────────────")

		maxShow := 5
		for i, lib := range alwaysNoise {
			if i >= maxShow {
				fmt.Fprintf(r.output, "  ... and %d more\n", len(alwaysNoise)-maxShow)
				break
			}
			fmt.Fprintf(r.output, "  • %-40s (%d files, %d APKs)\n",
				truncateString(lib.Prefix, 38), lib.TotalFiles, lib.SeenInAPKs)
		}
	}

	fmt.Fprintln(r.output)

	return nil
}

func (r *MLRunner) jsonStats() error {
	keywords := r.history.AggregateKeywordStats()
	libraries := r.history.AggregateLibraryStats()
	noisy := r.history.TopNoisyKeywords(10)
	alwaysNoise := r.history.AlwaysNoiseLibraries(2)

	// Convert to serializable
	noisyList := make([]map[string]interface{}, 0, len(noisy))
	for _, kw := range noisy {
		noisyList = append(noisyList, map[string]interface{}{
			"keyword":         kw.Keyword,
			"noise_ratio":     kw.NoiseRatio,
			"total_triggered": kw.TotalTriggered,
			"seen_in_apks":    kw.SeenInAPKs,
		})
	}

	alwaysNoiseList := make([]map[string]interface{}, 0, len(alwaysNoise))
	for _, lib := range alwaysNoise {
		alwaysNoiseList = append(alwaysNoiseList, map[string]interface{}{
			"prefix":       lib.Prefix,
			"category":     lib.Category,
			"total_files":  lib.TotalFiles,
			"seen_in_apks": lib.SeenInAPKs,
		})
	}

	encoder := json.NewEncoder(r.output)
	encoder.SetIndent("", "  ")

	return encoder.Encode(map[string]interface{}{
		"total_analyses":         r.history.Len(),
		"keywords_tracked":       len(keywords),
		"libraries_tracked":      len(libraries),
		"top_noisy_keywords":     noisyList,
		"always_noise_libraries": alwaysNoiseList,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEEDBACK
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MLRunner) markFeedback(target, action string) error {
	if r.history.Len() == 0 {
		return fmt.Errorf("no analysis history found, nothing to mark")
	}

	isKeyword := !containsPathSeparator(target)
	override := ml.UserOverride{
		Path:      target,
		Action:    action,
		Timestamp: time.Now(),
		Reason:    "user feedback via CLI",
	}

	// Если target похож на keyword (без /), отмечаем как keyword
	if isKeyword {
		override.Keyword = target
	} else {
		// Validating path to prevent injection and path traversal
		if strings.Contains(target, "..") || strings.Contains(target, ";") || strings.Contains(target, "'") {
			return fmt.Errorf("invalid path format for feedback")
		}
	}

	lastRecord := r.history.Last()
	if lastRecord != nil {
		override.APKName = lastRecord.APKName
	}
	if lastRecord != nil && len(lastRecord.MethodFeatures) > 0 {
		var matched *ml.MethodFeatureSnapshot
		matchesCount := 0
		for i := range lastRecord.MethodFeatures {
			mf := &lastRecord.MethodFeatures[i]
			if strings.Contains(mf.Path, target) ||
				strings.Contains(mf.ClassName, target) ||
				strings.Contains(mf.MethodName, target) ||
				strings.Contains(mf.Signature, target) {
				matched = mf
				matchesCount++
			}
		}
		if matchesCount == 1 && matched != nil {
			fCopy := matched.Features
			override.Features = &fCopy
		}
	}

	if ml.IsDuplicateUserOverride(r.history.Snapshot(), override) {
		if r.opts.JSON {
			return json.NewEncoder(r.output).Encode(map[string]interface{}{
				"status":  "skipped",
				"target":  target,
				"action":  action,
				"message": "Already marked",
			})
		}
		fmt.Fprintf(r.output, "Already marked %q as %s (skipped)\n", target, action)
		return nil
	}

	if err := r.history.AddUserOverride(override); err != nil {
		return fmt.Errorf("failed to add feedback: %w", err)
	}

	if err := r.history.Save(); err != nil {
		return fmt.Errorf("failed to save history: %w", err)
	}

	if r.opts.JSON {
		return json.NewEncoder(r.output).Encode(map[string]interface{}{
			"status":  "ok",
			"target":  target,
			"action":  action,
			"message": "Feedback recorded",
		})
	}

	fmt.Fprintf(r.output, "Marked %q as %s\n", target, action)
	fmt.Fprintln(r.output, "Feedback will improve future suggestions.")

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func containsPathSeparator(s string) bool {
	for _, c := range s {
		if c == '/' || c == '\\' {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHOW FEEDBACK
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MLRunner) showFeedback() error {
	if r.history.Len() == 0 {
		if r.opts.JSON {
			return json.NewEncoder(r.output).Encode(map[string]interface{}{
				"error":   "no_history",
				"message": "No analysis history found.",
			})
		}
		fmt.Fprintln(r.output, "No analysis history found.")
		return nil
	}

	// Build the reconciled effective view: latest decision wins and neutral
	// clears a previous decision.
	allOverrides := make(map[string]ml.UserOverride)
	records := r.history.Snapshot()

	for _, override := range ml.ResolveUserOverrides(records) {
		key := fmt.Sprintf("%s:%s", override.Action, ml.NormalizeFeedbackTarget(ml.UserOverrideTarget(override)))
		allOverrides[key] = override
	}

	if len(allOverrides) == 0 {
		if r.opts.JSON {
			return json.NewEncoder(r.output).Encode(map[string]interface{}{
				"total":     0,
				"noise":     0,
				"relevant":  0,
				"overrides": []interface{}{},
			})
		}
		fmt.Fprintln(r.output, "No user feedback found.")
		return nil
	}

	// Разделяем на noise и relevant
	noiseList := make([]ml.UserOverride, 0)
	relevantList := make([]ml.UserOverride, 0)

	for _, override := range allOverrides {
		switch override.Action {
		case "noise":
			noiseList = append(noiseList, override)
		case "relevant":
			relevantList = append(relevantList, override)
		}
	}

	// JSON output
	if r.opts.JSON {
		return json.NewEncoder(r.output).Encode(map[string]interface{}{
			"total":     len(allOverrides),
			"noise":     len(noiseList),
			"relevant":  len(relevantList),
			"overrides": allOverrides,
		})
	}

	// Terminal output
	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(r.output, "  ║           USER FEEDBACK                  ║")
	fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(r.output)
	fmt.Fprintf(r.output, "  Total overrides: %d\n", len(allOverrides))
	fmt.Fprintf(r.output, "  • Noise: %d\n", len(noiseList))
	fmt.Fprintf(r.output, "  • Relevant: %d\n\n", len(relevantList))

	if len(noiseList) > 0 {
		fmt.Fprintln(r.output, "  🔇 NOISE (ignored patterns):")
		fmt.Fprintln(r.output, "  ─────────────────────────────────────────")
		for i, override := range noiseList {
			if i >= 20 {
				fmt.Fprintf(r.output, "  ... and %d more\n", len(noiseList)-20)
				break
			}
			pattern := override.Path
			if pattern == "" {
				pattern = override.Keyword
			}
			fmt.Fprintf(r.output, "  • %s\n", pattern)
		}
		fmt.Fprintln(r.output)
	}

	if len(relevantList) > 0 {
		fmt.Fprintln(r.output, "  ⭐ RELEVANT (boosted patterns):")
		fmt.Fprintln(r.output, "  ─────────────────────────────────────────")
		for i, override := range relevantList {
			if i >= 20 {
				fmt.Fprintf(r.output, "  ... and %d more\n", len(relevantList)-20)
				break
			}
			pattern := override.Path
			if pattern == "" {
				pattern = override.Keyword
			}
			fmt.Fprintf(r.output, "  • %s\n", pattern)
		}
		fmt.Fprintln(r.output)
	}

	// Экспорт в файл
	outputDir := "analysis_output"
	if r.opts.Output != "" {
		outputDir = r.opts.Output
	}

	// Создаём директорию если нужно
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	feedbackFile := filepath.Join(outputDir, "USER_FEEDBACK.md")

	var buf strings.Builder
	buf.WriteString("# User Feedback\n\n")
	buf.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("Total overrides: %d\n\n", len(allOverrides)))

	if len(noiseList) > 0 {
		buf.WriteString("## 🔇 Noise Patterns (Ignored)\n\n")
		buf.WriteString(fmt.Sprintf("Total: %d patterns\n\n", len(noiseList)))
		for _, override := range noiseList {
			pattern := override.Path
			if pattern == "" {
				pattern = override.Keyword
			}
			buf.WriteString(fmt.Sprintf("- `%s`\n", pattern))
		}
		buf.WriteString("\n")
	}

	if len(relevantList) > 0 {
		buf.WriteString("## ⭐ Relevant Patterns (Boosted)\n\n")
		buf.WriteString(fmt.Sprintf("Total: %d patterns\n\n", len(relevantList)))
		for _, override := range relevantList {
			pattern := override.Path
			if pattern == "" {
				pattern = override.Keyword
			}
			buf.WriteString(fmt.Sprintf("- `%s`\n", pattern))
		}
		buf.WriteString("\n")
	}

	buf.WriteString("## Usage\n\n")
	buf.WriteString("These patterns are automatically applied during ML patch prediction:\n\n")
	buf.WriteString("- **Noise patterns** are filtered out from results\n")
	buf.WriteString("- **Relevant patterns** get +20% score boost\n\n")
	buf.WriteString("To add more feedback:\n")
	buf.WriteString("```bash\n")
	buf.WriteString("analyzer --mark-noise \"Lcom/google/ads/.*\"\n")
	buf.WriteString("analyzer --mark-relevant \"Lcom/myapp/premium/.*\"\n")
	buf.WriteString("```\n")

	if err := os.WriteFile(feedbackFile, []byte(buf.String()), 0644); err != nil {
		return fmt.Errorf("failed to write feedback file: %w", err)
	}

	fmt.Fprintf(r.output, "  ✓ Exported to: %s\n\n", feedbackFile)

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// APPLY ML SUGGESTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MLRunner) applyMLSuggestions() error {
	if r.history.Len() == 0 {
		return fmt.Errorf("no analysis history found")
	}

	// Получаем все рекомендации
	cfg := ml.DefaultSuggesterConfig()
	cfg.ConfidenceThreshold = r.opts.MLConfidence
	if r.opts.MLMaxSuggestions > 0 {
		cfg.MaxDisplaySuggestions = r.opts.MLMaxSuggestions
	}

	suggester := ml.NewMLSuggester(
		r.history,
		ml.WithSuggesterConfig(cfg),
		ml.WithOutput(r.output),
	)

	result := suggester.Analyze()

	if len(result.Suggestions) == 0 {
		fmt.Fprintln(r.output, "No suggestions available to apply.")
		return nil
	}

	// Парсим номера для применения
	indices, err := parseApplyIndices(r.opts.MLApply, len(result.Suggestions))
	if err != nil {
		return fmt.Errorf("invalid --ml-apply format: %w", err)
	}

	// Фильтруем по confidence если "all"
	if r.opts.MLApply == "all" {
		filtered := make([]int, 0)
		for i, sugg := range result.Suggestions {
			if sugg.Confidence >= 0.90 {
				filtered = append(filtered, i)
			}
		}
		indices = filtered
	}

	if len(indices) == 0 {
		fmt.Fprintln(r.output, "No suggestions match the criteria.")
		return nil
	}

	// Применяем выбранные рекомендации
	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(r.output, "  ║       APPLYING ML SUGGESTIONS            ║")
	fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(r.output)

	applied := 0
	skipped := 0

	for _, idx := range indices {
		if idx >= len(result.Suggestions) {
			continue
		}

		sugg := result.Suggestions[idx]

		// Определяем action на основе типа рекомендации
		action := "noise"
		pattern := sugg.Target

		// Применяем рекомендацию
		if err := r.applyOneSuggestion(sugg, idx+1); err != nil {
			fmt.Fprintf(r.output, "  ✗ #%d: %s (error: %v)\n", idx+1, pattern, err)
			skipped++
		} else {
			fmt.Fprintf(r.output, "  ✓ #%d: %s → marked as %s\n", idx+1, pattern, action)
			applied++
		}
	}

	fmt.Fprintln(r.output)
	fmt.Fprintf(r.output, "  Applied: %d, Skipped: %d\n", applied, skipped)
	fmt.Fprintln(r.output)

	return nil
}

func (r *MLRunner) applyOneSuggestion(sugg ml.Suggestion, num int) error {
	// Определяем action
	action := "noise"
	if sugg.Action == "relevant" {
		action = "relevant"
	}

	isKeyword := !containsPathSeparator(sugg.Target)
	if existing, ok := ml.FindUserOverrideDecision(r.history.Snapshot(), sugg.Target, isKeyword); ok && existing.Action == action {
		return fmt.Errorf("already marked")
	}

	// Создаем override
	override := ml.UserOverride{
		Path:      sugg.Target,
		Action:    action,
		Timestamp: time.Now(),
		Reason:    fmt.Sprintf("ML suggestion #%d (confidence: %.0f%%)", num, sugg.Confidence*100),
	}

	// Если похоже на keyword
	if isKeyword {
		override.Keyword = sugg.Target
	}

	if err := r.history.AddUserOverride(override); err != nil {
		return err
	}

	return r.history.Save()
}

// parseApplyIndices парсит строку вида "1,3,5" или "1-10" или "all"
func parseApplyIndices(input string, maxCount int) ([]int, error) {
	if input == "all" {
		// Вернем все индексы, фильтрация по confidence будет позже
		indices := make([]int, maxCount)
		for i := 0; i < maxCount; i++ {
			indices[i] = i
		}
		return indices, nil
	}

	indices := make([]int, 0)
	parts := strings.Split(input, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Проверяем диапазон (1-10)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start number: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end number: %s", rangeParts[1])
			}

			if start < 1 || end > maxCount || start > end {
				return nil, fmt.Errorf("invalid range: %d-%d (max: %d)", start, end, maxCount)
			}

			for i := start; i <= end; i++ {
				indices = append(indices, i-1) // 0-based
			}
		} else {
			// Одиночный номер
			num, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid number: %s", part)
			}

			if num < 1 || num > maxCount {
				return nil, fmt.Errorf("number out of range: %d (max: %d)", num, maxCount)
			}

			indices = append(indices, num-1) // 0-based
		}
	}

	return indices, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN EFFECTIVENESS STATS
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MLRunner) showPatternStats() error {
	// Load pattern tracker from default location
	tracker, err := r.loadPatternTracker()
	if err != nil {
		return fmt.Errorf("failed to load pattern tracker: %w", err)
	}

	// Create reporter
	reporter := ml.NewPatternEffectivenessReporter(tracker, r.output)

	// Display report based on output format
	if r.opts.JSON {
		return reporter.DisplayJSONReport()
	}

	return reporter.DisplayReport()
}

func (r *MLRunner) exportPatternStats() error {
	// Load pattern tracker from default location
	tracker, err := r.loadPatternTracker()
	if err != nil {
		return fmt.Errorf("failed to load pattern tracker: %w", err)
	}

	// Create reporter
	reporter := ml.NewPatternEffectivenessReporter(tracker, r.output)

	// Export to JSON file
	if err := reporter.ExportJSON(r.opts.ExportPatternStats); err != nil {
		return fmt.Errorf("failed to export pattern stats: %w", err)
	}

	if !r.opts.Quiet {
		fmt.Fprintf(r.errOut, "Pattern effectiveness data exported to %s\n", r.opts.ExportPatternStats)
	}

	return nil
}

func (r *MLRunner) loadPatternTracker() (*ml.PatternTracker, error) {
	// Get default pattern metrics path
	metricsPath, err := ml.DefaultPatternMetricsPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics path: %w", err)
	}

	// Create tracker and load from file
	tracker := ml.NewPatternTracker()
	if err := tracker.LoadFromFile(metricsPath); err != nil {
		// If file doesn't exist, return empty tracker (not an error)
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load metrics: %w", err)
		}
	}

	return tracker, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// IMPORT FEEDBACK FROM JSON
// ═══════════════════════════════════════════════════════════════════════════════

func (r *MLRunner) importFeedback() error {
	// Validate file exists
	if _, err := os.Stat(r.opts.FeedbackFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("feedback file not found: %s", r.opts.FeedbackFile)
		}
		return fmt.Errorf("cannot access feedback file: %w", err)
	}

	// Read feedback file
	data, err := os.ReadFile(r.opts.FeedbackFile)
	if err != nil {
		return fmt.Errorf("failed to read feedback file: %w", err)
	}

	// Parse JSON - expect array of feedback entries
	type FeedbackEntry struct {
		PatternID string `json:"pattern_id"`
		Outcome   string `json:"outcome"` // "true_positive", "false_positive", "false_negative", "neutral"
		Note      string `json:"note,omitempty"`
	}

	var entries []FeedbackEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse feedback JSON: %w", err)
	}

	if len(entries) == 0 {
		if r.opts.JSON {
			return json.NewEncoder(r.output).Encode(map[string]interface{}{
				"status":  "skipped",
				"message": "No feedback entries found in file",
			})
		}
		fmt.Fprintln(r.output, "No feedback entries found in file.")
		return nil
	}

	// Load pattern tracker
	tracker, err := r.loadPatternTracker()
	if err != nil {
		return fmt.Errorf("failed to load pattern tracker: %w", err)
	}

	// Import feedback entries
	imported := 0
	skipped := 0
	overrideCount := 0

	for _, entry := range entries {
		// Validate outcome type
		var outcome ml.OutcomeType
		var action string
		switch entry.Outcome {
		case "true_positive":
			outcome = ml.OutcomeTruePositive
			action = "relevant"
		case "false_positive":
			outcome = ml.OutcomeFalsePositive
			action = "noise"
		case "false_negative":
			outcome = ml.OutcomeFalseNegative
			// A false negative is a missed relevant signal. Treating it as noise
			// suppresses the exact pattern the user asked us to recover.
			action = ml.FeedbackRelevant
		case "neutral":
			action = "neutral"
		default:
			if !r.opts.Quiet {
				fmt.Fprintf(r.errOut, "Warning: Invalid outcome type %q for pattern %s (skipped)\n",
					entry.Outcome, entry.PatternID)
			}
			skipped++
			continue
		}

		// 1. Record outcome in pattern effectiveness tracker (if not neutral)
		if action != "neutral" {
			tracker.RecordOutcome(entry.PatternID, outcome)
		}
		imported++

		// 2. Automatically record User Override for direct scan feedback mapping.
		isKeyword := !containsPathSeparator(entry.PatternID)
		existing, found := ml.FindUserOverrideDecision(r.history.Snapshot(), entry.PatternID, isKeyword)
		alreadyExists := found && existing.Action == action

		if !alreadyExists {
			reason := fmt.Sprintf("Imported from HTML report feedback (%s)", entry.Outcome)
			if entry.Note != "" {
				reason = entry.Note
			}
			override := ml.UserOverride{
				Path:      entry.PatternID,
				Action:    action,
				Timestamp: time.Now(),
				Reason:    reason,
			}
			if isKeyword {
				override.Keyword = entry.PatternID
			}

			if err := r.history.AddUserOverride(override); err == nil {
				overrideCount++
			}
		}
	}

	// Save updated tracker
	metricsPath, err := ml.DefaultPatternMetricsPath()
	if err != nil {
		return fmt.Errorf("failed to get metrics path: %w", err)
	}

	// Ensure directory exists
	metricsDir := filepath.Dir(metricsPath)
	if err := os.MkdirAll(metricsDir, 0755); err != nil {
		return fmt.Errorf("failed to create metrics directory: %w", err)
	}

	if err := tracker.SaveToFile(metricsPath); err != nil {
		return fmt.Errorf("failed to save pattern metrics: %w", err)
	}

	// Save updated history (which holds user overrides)
	if err := r.history.Save(); err != nil {
		return fmt.Errorf("failed to save analysis history: %w", err)
	}

	// Output results
	if r.opts.JSON {
		return json.NewEncoder(r.output).Encode(map[string]interface{}{
			"status":            "ok",
			"imported_metrics":  imported,
			"created_overrides": overrideCount,
			"skipped":           skipped,
			"total":             len(entries),
		})
	}

	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(r.output, "  ║       FEEDBACK IMPORT COMPLETE           ║")
	fmt.Fprintln(r.output, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(r.output)
	fmt.Fprintf(r.output, "  Imported:  %d pattern effectiveness metrics\n", imported)
	fmt.Fprintf(r.output, "  Generated: %d direct user overrides (history)\n", overrideCount)
	if skipped > 0 {
		fmt.Fprintf(r.output, "  Skipped:   %d entries (invalid format)\n", skipped)
	}
	fmt.Fprintf(r.output, "  Total:     %d entries processed\n", len(entries))
	fmt.Fprintln(r.output)
	fmt.Fprintln(r.output, "  Pattern metrics and user overrides successfully updated.")
	fmt.Fprintln(r.output, "  Feedback will automatically suppress noise or boost relevant rules on next scan.")
	fmt.Fprintln(r.output)

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPERIMENTAL MODULES — list view
// ═══════════════════════════════════════════════════════════════════════════════

// listExperimentalModules prints available experimental modules and presets.
// Wired through MLRunner so users can call --ml-ex-list without a target.
func (r *MLRunner) listExperimentalModules() error {
	app := &App{opts: r.opts}
	return app.listExperimentalModules()
}
